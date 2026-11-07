package com.whitetea.baretrack.forensics;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.Inflater;

/** Embedded cover-art examination: dimensions, EXIF, XMP, PNG text chunks, ICC and image hash. */
final class ImageInspector {
    private static final Pattern XMP_ATTR = Pattern.compile(
            "(xmp:CreatorTool|xmp:CreateDate|xmp:ModifyDate|xmp:MetadataDate|xmpMM:DocumentID|xmpMM:InstanceID|"
                    + "xmpMM:OriginalDocumentID|stEvt:softwareAgent|Iptc4xmpExt:DigitalSourceType|photoshop:Credit|"
                    + "dc:creator|dc:rights|tiff:Software|exif:Software|c2pa:[A-Za-z]+)\\s*=\\s*\"([^\"]{1,400})\"");
    private static final Pattern XMP_ELEM = Pattern.compile(
            "<(xmp:CreatorTool|stEvt:softwareAgent|Iptc4xmpExt:DigitalSourceType|xmpMM:DocumentID|xmpMM:InstanceID|"
                    + "dc:creator|dc:rights|dc:title|dc:description)>\\s*(?:<rdf:(?:Seq|Alt|Bag)>\\s*<rdf:li[^>]*>)?([^<]{1,400})<");

    private final ForensicReport report;
    private final TextForensics text;

    ImageInspector(ForensicReport report, TextForensics text) {
        this.report = report;
        this.text = text;
    }

    void inspect(String source, byte[] data, long fileOffset, String declaredMime) {
        if (data == null || data.length == 0) return;
        dims = "";
        String src = source + " image";
        report.field(ForensicReport.SECTION_METADATA, src, "Size", Bin.bytes(data.length), fileOffset);
        if (declaredMime != null && !declaredMime.isEmpty()) report.field(ForensicReport.SECTION_METADATA, src, "Declared type", declaredMime, fileOffset);
        report.field(ForensicReport.SECTION_METADATA, src, "Image SHA-256 (match against known platform artwork)", sha256(data), fileOffset);
        String format;
        if (data.length > 3 && (data[0] & 0xFF) == 0xFF && (data[1] & 0xFF) == 0xD8) {
            format = "JPEG";
            jpeg(src, data, fileOffset);
        } else if (data.length > 8 && Bin.ascii(data, 1, "PNG")) {
            format = "PNG";
            png(src, data, fileOffset);
        } else if (data.length > 12 && Bin.ascii(data, 0, "RIFF") && Bin.ascii(data, 8, "WEBP")) {
            format = "WebP";
        } else if (data.length > 6 && Bin.ascii(data, 0, "GIF8")) {
            format = "GIF";
            report.field(ForensicReport.SECTION_METADATA, src, "Dimensions", Bin.u16le(data, 6) + "×" + Bin.u16le(data, 8), fileOffset);
        } else {
            format = "unrecognised (" + Bin.hex(data, 0, Math.min(8, data.length)) + ")";
        }
        report.field(ForensicReport.SECTION_METADATA, src, "Detected format", format, fileOffset);
        if (declaredMime != null && !declaredMime.isEmpty()) {
            String m = declaredMime.toLowerCase(Locale.ROOT);
            boolean mismatch = (format.equals("JPEG") && !m.contains("jp")) || (format.equals("PNG") && !m.contains("png"));
            if (mismatch) {
                report.evidence(Evidence.Tier.INFO, "Artwork", "Artwork MIME type does not match its bytes",
                        "Declared " + declaredMime + " but the data is " + format + ".", fileOffset);
            }
        }
        report.fingerprint.putIfAbsent("artwork", dims.isEmpty() ? format : format + " " + dims);
    }

    private String dims = "";

    private void jpeg(String src, byte[] d, long base) {
        int p = 2;
        ByteArrayOutputStream jumbf = new ByteArrayOutputStream();
        StringBuilder markers = new StringBuilder();
        while (p + 4 <= d.length) {
            if ((d[p] & 0xFF) != 0xFF) break;
            int marker = d[p + 1] & 0xFF;
            if (marker == 0xD8 || (marker >= 0xD0 && marker <= 0xD7) || marker == 0x01) { p += 2; continue; }
            if (marker == 0xD9 || marker == 0xDA) {
                markers.append(marker == 0xDA ? "SOS" : "EOI");
                break;
            }
            int len = Bin.u16be(d, p + 2);
            if (len < 2 || p + 2 + len > d.length) break;
            int s = p + 4, n = len - 2;
            markers.append(String.format(Locale.ROOT, "%s ", markerName(marker)));
            if (marker == 0xE1 && n > 6 && Bin.ascii(d, s, "Exif")) {
                exif(src, d, s + 6, n - 6, base < 0 ? -1 : base + s + 6);
            } else if (marker == 0xE1 && Bin.ascii(d, s, "http://ns.adobe.com/xap/1.0/")) {
                int start = s + 29;
                xmp(src, new String(d, start, Math.max(0, s + n - start), StandardCharsets.UTF_8), base < 0 ? -1 : base + start);
            } else if (marker == 0xE0 && Bin.ascii(d, s, "JFIF")) {
                report.field(ForensicReport.SECTION_METADATA, src, "JFIF", "v" + d[s + 5] + "." + d[s + 6], -1);
            } else if (marker == 0xE2 && Bin.ascii(d, s, "ICC_PROFILE")) {
                icc(src, d, s + 14, n - 14);
            } else if (marker == 0xEB && n > 8 && Bin.ascii(d, s, "JP")) {
                // C2PA in JPEG: APP11 'JP' + box instance (2) + sequence (4) + JUMBF box data.
                int seq = (int) Bin.u32be(d, s + 4);
                int payload = s + 8;
                if (seq == 1) jumbf.write(d, payload, s + n - payload);
                else if (payload + 8 <= s + n) jumbf.write(d, payload + 8, s + n - payload - 8);
            } else if (marker == 0xED && Bin.ascii(d, s, "Photoshop")) {
                report.field(ForensicReport.SECTION_METADATA, src, "Photoshop IRB", n + " bytes", -1);
            } else if (marker == 0xFE) {
                String c = Bin.latin1(d, s, n);
                report.field(ForensicReport.SECTION_METADATA, src, "JPEG comment", c, -1);
                text.inspect(src, "JPEG comment", c, -1);
            } else if (marker == 0xC0 || marker == 0xC1 || marker == 0xC2) {
                dims = Bin.u16be(d, s + 3) + "×" + Bin.u16be(d, s + 1);
                report.field(ForensicReport.SECTION_METADATA, src, "Dimensions", dims + (marker == 0xC2 ? " progressive" : " baseline")
                        + ", " + (d[s + 5] & 0xFF) + " components", -1);
            }
            p += 2 + len;
        }
        report.field(ForensicReport.SECTION_METADATA, src, "JPEG segment order", markers.toString().trim(), -1);
        if (jumbf.size() > 0) {
            report.field(ForensicReport.SECTION_C2PA, src, "Image-level C2PA (APP11 JUMBF)", jumbf.size() + " bytes", -1);
            C2paInspector.Result r = C2paInspector.inspectStore(jumbf.toByteArray(), null, 0, report, src + " C2PA");
            if (r != null) report.evidence(Evidence.Tier.INFO, "Artwork", "Cover art carries its own C2PA credential",
                    "Generator: " + r.claimGenerator + ". This credential describes the image, not necessarily the audio.", -1);
        }
    }

    private void exif(String src, byte[] d, int tiff, int n, long base) {
        if (n < 8) return;
        boolean le = d[tiff] == 'I';
        int ifd0 = (int) (le ? Bin.u32le(d, tiff + 4) : Bin.u32be(d, tiff + 4));
        report.field(ForensicReport.SECTION_METADATA, src, "EXIF", (le ? "little" : "big") + "-endian TIFF, " + n + " bytes", base);
        int next = ifd(src, d, tiff, n, ifd0, le, "IFD0");
        if (next > 0 && next < n) {
            report.field(ForensicReport.SECTION_METADATA, src, "EXIF IFD1", "present — an embedded thumbnail, which can show the original image before edits", -1);
            report.evidence(Evidence.Tier.INFO, "Artwork", "Cover art contains an EXIF thumbnail",
                    "Thumbnails are often left untouched when the main image is edited.", -1);
        }
    }

    private int ifd(String src, byte[] d, int tiff, int n, int off, boolean le, String name) {
        if (off <= 0 || off + 2 > n) return 0;
        int count = le ? Bin.u16le(d, tiff + off) : Bin.u16be(d, tiff + off);
        if (count > 512) return 0;
        for (int i = 0; i < count; i++) {
            int e = tiff + off + 2 + i * 12;
            if (e + 12 > tiff + n) return 0;
            int tag = le ? Bin.u16le(d, e) : Bin.u16be(d, e);
            int type = le ? Bin.u16le(d, e + 2) : Bin.u16be(d, e + 2);
            long cnt = le ? Bin.u32le(d, e + 4) : Bin.u32be(d, e + 4);
            long val = le ? Bin.u32le(d, e + 8) : Bin.u32be(d, e + 8);
            String label = exifTag(tag);
            if (tag == 0x8769) { ifd(src, d, tiff, n, (int) val, le, "ExifIFD"); continue; }
            if (label == null || type != 2) continue;
            int at = cnt <= 4 ? e + 8 : tiff + (int) val;
            if (at < 0 || at + cnt > d.length || cnt > 4096) continue;
            String v = Bin.fixed(d, at, (int) cnt);
            report.field(ForensicReport.SECTION_METADATA, src, "EXIF " + label, v, -1);
            text.inspect(src, "EXIF " + label, v, -1);
        }
        int nextAt = tiff + off + 2 + count * 12;
        if (nextAt + 4 > tiff + n) return 0;
        return (int) (le ? Bin.u32le(d, nextAt) : Bin.u32be(d, nextAt));
    }

    private static String exifTag(int tag) {
        switch (tag) {
            case 0x010E: return "ImageDescription";
            case 0x010F: return "Make";
            case 0x0110: return "Model";
            case 0x0131: return "Software";
            case 0x0132: return "DateTime";
            case 0x013B: return "Artist";
            case 0x8298: return "Copyright";
            case 0x9003: return "DateTimeOriginal";
            case 0x9004: return "DateTimeDigitized";
            case 0xA420: return "ImageUniqueID";
            case 0x9C9B: return "XPTitle";
            default: return null;
        }
    }

    void xmp(String src, String xml, long offset) {
        report.field(ForensicReport.SECTION_METADATA, src, "XMP packet", xml.length() + " chars", offset);
        Matcher m = XMP_ATTR.matcher(xml);
        while (m.find()) emitXmp(src, m.group(1), m.group(2), offset);
        m = XMP_ELEM.matcher(xml);
        while (m.find()) emitXmp(src, m.group(1), m.group(2).trim(), offset);
        text.inspect(src, "XMP", xml, offset);
    }

    private void emitXmp(String src, String key, String value, long offset) {
        report.field(ForensicReport.SECTION_METADATA, src, "XMP " + key, value, offset);
        if (key.contains("DigitalSourceType") && value.toLowerCase(Locale.ROOT).contains("algorithmicmedia")) {
            report.evidence(Evidence.Tier.PROBABLE, "AI declaration", "XMP declares algorithmic (AI) origin",
                    key + " = " + value, offset);
        }
    }

    private void icc(String src, byte[] d, int s, int n) {
        if (n < 132) return;
        String cmm = Bin.fourcc(d, s + 4);
        String creator = Bin.fourcc(d, s + 80);
        report.field(ForensicReport.SECTION_METADATA, src, "ICC profile", "CMM " + cmm + ", creator " + creator + ", " + n + " bytes", -1);
    }

    private void png(String src, byte[] d, long base) {
        int p = 8;
        StringBuilder order = new StringBuilder();
        while (p + 12 <= d.length) {
            int len = (int) Bin.u32be(d, p);
            String type = Bin.fourcc(d, p + 4);
            int s = p + 8;
            if (len < 0 || s + len > d.length) break;
            order.append(type).append(' ');
            if (type.equals("IHDR") && len >= 13) {
                dims = Bin.u32be(d, s) + "×" + Bin.u32be(d, s + 4);
                report.field(ForensicReport.SECTION_METADATA, src, "Dimensions", dims + ", bit depth " + d[s + 8] + ", colour type " + d[s + 9], -1);
            } else if (type.equals("tEXt") || type.equals("zTXt") || type.equals("iTXt")) {
                int z = s;
                while (z < s + len && d[z] != 0) z++;
                String key = Bin.latin1(d, s, z - s);
                String value;
                if (type.equals("tEXt")) value = Bin.latin1(d, z + 1, s + len - z - 1);
                else if (type.equals("zTXt")) value = inflateText(d, z + 2, s + len - z - 2, false);
                else {
                    boolean compressed = z + 1 < d.length && d[z + 1] == 1;
                    int q = z + 3;
                    for (int k = 0; k < 2; k++) { while (q < s + len && d[q] != 0) q++; q++; }
                    value = compressed ? inflateText(d, q, s + len - q, true) : Bin.utf8(d, q, s + len - q);
                }
                report.field(ForensicReport.SECTION_METADATA, src, "PNG " + type + " " + key, value, base < 0 ? -1 : base + s);
                text.inspect(src, "PNG " + key, value, base < 0 ? -1 : base + s);
                if (key.equals("XML:com.adobe.xmp")) xmp(src, value, base < 0 ? -1 : base + s);
                String lk = key.toLowerCase(Locale.ROOT);
                if (lk.equals("parameters") || lk.equals("prompt") || lk.equals("workflow")) {
                    report.evidence(Evidence.Tier.SUPPORTING, "Artwork", "Cover art carries image-generator parameters ('" + key + "')",
                            "Text chunks named 'parameters'/'prompt'/'workflow' are written by Stable Diffusion front-ends and ComfyUI. "
                                    + "This concerns the artwork, not the audio.", base < 0 ? -1 : base + s);
                }
            } else if (type.equals("eXIf")) {
                exif(src, d, s, len, -1);
            } else if (type.equals("caBX")) {
                byte[] store = new byte[len];
                System.arraycopy(d, s, store, 0, len);
                C2paInspector.inspectStore(store, null, 0, report, src + " C2PA");
            } else if (type.equals("IEND")) {
                if (s + len + 4 < d.length) {
                    report.evidence(Evidence.Tier.SUPPORTING, "Artwork", "Data appended after the PNG end marker",
                            (d.length - (s + len + 4)) + " bytes after IEND.", -1);
                }
                break;
            }
            p = s + len + 4;
        }
        report.field(ForensicReport.SECTION_METADATA, src, "PNG chunk order", order.toString().trim(), -1);
    }

    private static String inflateText(byte[] d, int o, int n, boolean utf8) {
        if (n <= 0) return "";
        Inflater inf = new Inflater();
        try {
            inf.setInput(d, o, n);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            while (!inf.finished() && out.size() < 1 << 20) {
                int c = inf.inflate(buf);
                if (c == 0 && (inf.needsInput() || inf.needsDictionary())) break;
                out.write(buf, 0, c);
            }
            return new String(out.toByteArray(), utf8 ? StandardCharsets.UTF_8 : StandardCharsets.ISO_8859_1);
        } catch (Exception e) {
            return "(compressed text could not be inflated)";
        } finally {
            inf.end();
        }
    }

    private static String markerName(int m) {
        if (m >= 0xE0 && m <= 0xEF) return "APP" + (m - 0xE0);
        switch (m) {
            case 0xDB: return "DQT";
            case 0xC4: return "DHT";
            case 0xC0: return "SOF0";
            case 0xC1: return "SOF1";
            case 0xC2: return "SOF2";
            case 0xDD: return "DRI";
            case 0xFE: return "COM";
            default: return String.format(Locale.ROOT, "FF%02X", m);
        }
    }

    static String sha256(byte[] data) {
        try {
            return Bin.hex(MessageDigest.getInstance("SHA-256").digest(data));
        } catch (Exception e) {
            return "unavailable";
        }
    }
}
