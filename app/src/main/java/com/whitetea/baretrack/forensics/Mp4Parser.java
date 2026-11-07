package com.whitetea.baretrack.forensics;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;

/** ISO base media (MP4/M4A/MOV) atom tree, iTunes/QuickTime metadata, timestamps and uuid boxes. */
final class Mp4Parser {
    private static final String C2PA_UUID = "d8fec3d61b0e483c92975828877ec481";
    private static final String XMP_UUID = "be7acfcb97a942e89c71999491e3afac";

    private final Scan s;
    private final List<String> topOrder = new ArrayList<>();
    private final List<String> keys = new ArrayList<>();
    private String handler = "";

    private Mp4Parser(Scan s) { this.s = s; }

    static void parse(Scan s, long start, long end) throws IOException {
        Mp4Parser p = new Mp4Parser(s);
        s.report.container = "ISO base media (MP4/M4A family)";
        long stop = p.walk(start, end, 0, "");
        s.report.fingerprint.put("mp4.atomOrder", Bin.join(",", p.topOrder));
        s.encoder("MP4", "Top-level atom order", Bin.join(",", p.topOrder), start);
        if (!p.topOrder.isEmpty()) {
            int moov = p.topOrder.indexOf("moov"), mdat = p.topOrder.indexOf("mdat");
            if (moov >= 0 && mdat >= 0) {
                s.encoder("MP4", "Layout", moov < mdat ? "moov before mdat (fast-start / streaming optimised)" : "mdat before moov (written in one pass)", start);
            }
        }
        if (stop < end) {
            byte[] tail = Bin.read(s.file, stop, (int) Math.min(end - stop, 1 << 20));
            s.report.node(0, "Bytes after the last atom", stop, end - stop, Bin.preview(tail, 0, tail.length, 64));
            if (!Bin.isAllZero(tail, 0, tail.length)) {
                s.report.evidence(Evidence.Tier.SUPPORTING, "Hidden data", "Data after the last MP4 atom",
                        (end - stop) + " bytes: " + Bin.preview(tail, 0, tail.length, 96), stop);
            }
        }
    }

    private long walk(long start, long end, int depth, String parent) throws IOException {
        long p = start;
        int guard = 0;
        while (p + 8 <= end && guard++ < 10000) {
            byte[] h = Bin.read(s.file, p, 16);
            long size = Bin.u32be(h, 0);
            String type = Bin.fourcc(h, 4);
            int header = 8;
            if (size == 1 && h.length >= 16) { size = Bin.u64be(h, 8); header = 16; }
            else if (size == 0) size = end - p;
            if (size < header || p + size > end || !type.matches("[ -~©]{4}")) {
                if (depth == 0) return p;
                s.report.evidence(Evidence.Tier.INFO, "Container", "Malformed atom inside '" + parent + "'", "at " + Bin.hexOffset(p), p);
                return p;
            }
            long body = p + header, bodyEnd = p + size;
            if (depth == 0) topOrder.add(type);
            String path = parent.isEmpty() ? type : parent + "/" + type;
            s.report.node(depth, "Atom '" + type + "'", p, size, describe(path));
            try {
                atom(type, path, body, bodyEnd, depth);
            } catch (RuntimeException e) {
                s.report.field(ForensicReport.SECTION_METADATA, "Atom " + path, "Parse error", e.getClass().getSimpleName(), p);
            }
            p = bodyEnd;
        }
        return p;
    }

    private static String describe(String path) {
        if (path.endsWith("mdat")) return "media data";
        if (path.endsWith("moov")) return "movie header container";
        if (path.endsWith("ilst")) return "iTunes metadata list";
        return "";
    }

    private void atom(String type, String path, long b, long e, int depth) throws IOException {
        switch (type) {
            case "moov": case "trak": case "mdia": case "minf": case "stbl": case "udta": case "edts": case "dinf":
            case "mvex": case "moof": case "traf": case "sinf": case "schi": case "tref": case "wave":
                walk(b, e, depth + 1, path);
                break;
            case "meta": {
                byte[] peek = Bin.read(s.file, b, 8);
                String next = peek.length >= 8 ? Bin.fourcc(peek, 4) : "";
                boolean full = !(next.equals("hdlr") || next.equals("keys") || next.equals("ilst"));
                walk(full ? b + 4 : b, e, depth + 1, path);
                break;
            }
            case "ftyp": {
                byte[] d = Bin.read(s.file, b, (int) Math.min(e - b, 256));
                StringBuilder compat = new StringBuilder();
                for (int i = 8; i + 4 <= d.length; i += 4) compat.append(i > 8 ? "," : "").append(Bin.fourcc(d, i).trim());
                String v = "major " + Bin.fourcc(d, 0) + ", minor " + Bin.u32be(d, 4) + ", compatible " + compat;
                s.encoder("ftyp", "File type", v, b);
                s.report.fingerprint.put("mp4.ftyp", Bin.fourcc(d, 0).trim() + "/" + compat);
                break;
            }
            case "mvhd": case "mdhd": case "tkhd": {
                byte[] d = Bin.read(s.file, b, 40);
                int version = d[0] & 0xFF;
                long created = version == 1 ? Bin.u64be(d, 4) : Bin.u32be(d, 4);
                long modified = version == 1 ? Bin.u64be(d, 12) : Bin.u32be(d, 8);
                String src = "MP4 " + type;
                s.meta(src, "Creation time", macTime(created), b);
                s.meta(src, "Modification time", macTime(modified), b);
                if (!type.equals("tkhd")) {
                    long timescale = version == 1 ? Bin.u32be(d, 20) : Bin.u32be(d, 12);
                    long duration = version == 1 ? Bin.u64be(d, 24) : Bin.u32be(d, 16);
                    if (timescale > 0) {
                        s.encoder(src, "Timescale / duration", timescale + " / " + duration + String.format(Locale.ROOT, " (%.3f s)", duration / (double) timescale), b);
                        if (type.equals("mdhd")) s.measuredDurationSec = duration / (double) timescale;
                    }
                    if (type.equals("mdhd")) {
                        int lang = Bin.u16be(d, version == 1 ? 32 : 20);
                        String code = "" + (char) (((lang >> 10) & 31) + 0x60) + (char) (((lang >> 5) & 31) + 0x60) + (char) ((lang & 31) + 0x60);
                        s.meta(src, "Language", code, b);
                    }
                }
                if (created == 0) s.report.fingerprint.putIfAbsent("mp4.creationTime", "zero");
                else s.report.fingerprint.putIfAbsent("mp4.creationTime", "set");
                break;
            }
            case "hdlr": {
                byte[] d = Bin.read(s.file, b, (int) Math.min(e - b, 512));
                if (d.length < 24) return;
                String htype = Bin.fourcc(d, 8);
                String name = d.length > 24 ? Bin.fixed(d, 24, d.length - 24) : "";
                if (!name.isEmpty() && name.charAt(0) < 0x20) name = name.substring(1);
                s.encoder("hdlr " + path, "Handler", htype + (name.isEmpty() ? "" : " \"" + name + "\""), b);
                if (path.contains("mdia")) { handler = htype + " " + name; s.report.fingerprint.put("mp4.handler", handler.trim()); }
                s.text.inspect("hdlr", "name", name, b);
                break;
            }
            case "stsd": {
                byte[] d = Bin.read(s.file, b, (int) Math.min(e - b, 4096));
                if (d.length < 16) return;
                long count = Bin.u32be(d, 4);
                int p = 8;
                for (int i = 0; i < count && p + 36 <= d.length; i++) {
                    int size = (int) Bin.u32be(d, p);
                    String fmt = Bin.fourcc(d, p + 4);
                    int ch = Bin.u16be(d, p + 24), bits = Bin.u16be(d, p + 26);
                    long rate = Bin.u32be(d, p + 32) >>> 16;
                    String codec = fmt + ", " + ch + " ch, " + bits + "-bit, " + rate + " Hz";
                    if (fmt.equals("mp4a")) {
                        int esds = indexOf(d, "esds", p, Math.min(d.length, p + size));
                        if (esds > 0) codec += ", " + esdsInfo(d, esds + 4, Math.min(d.length, p + size));
                    }
                    s.report.codec = codec;
                    s.encoder("stsd", "Sample entry", codec, b + p);
                    s.report.fingerprint.put("mp4.codec", codec);
                    if (size <= 0) break;
                    p += size;
                }
                break;
            }
            case "keys": {
                byte[] d = Bin.read(s.file, b, (int) Math.min(e - b, 1 << 16));
                long count = d.length >= 8 ? Bin.u32be(d, 4) : 0;
                int p = 8;
                for (int i = 0; i < count && p + 8 <= d.length; i++) {
                    int size = (int) Bin.u32be(d, p);
                    if (size < 8) break;
                    keys.add(Bin.latin1(d, p + 8, size - 8));
                    p += size;
                }
                break;
            }
            case "ilst":
                ilst(b, e);
                break;
            case "uuid": {
                byte[] d = Bin.read(s.file, b, (int) Math.min(e - b, 64L << 20));
                if (d.length < 16) return;
                String uuid = Bin.hex(d, 0, 16);
                if (uuid.equals(C2PA_UUID)) {
                    int q = 16 + 4;
                    int z = q;
                    while (z < d.length && d[z] != 0) z++;
                    String purpose = Bin.latin1(d, q, z - q);
                    q = z + 1;
                    s.report.field(ForensicReport.SECTION_C2PA, "MP4 uuid box", "Purpose", purpose, b);
                    if (purpose.equals("manifest")) {
                        q += 8;
                        if (q < d.length) s.c2paStore(java.util.Arrays.copyOfRange(d, q, d.length), b + q, "MP4 C2PA uuid box");
                    }
                } else if (uuid.equals(XMP_UUID)) {
                    s.images.xmp("MP4 XMP uuid", new String(d, 16, d.length - 16, StandardCharsets.UTF_8), b + 16);
                } else {
                    s.meta("MP4 uuid " + uuid, "Content", Bin.preview(d, 16, d.length - 16, 120), b);
                    s.report.evidence(Evidence.Tier.INFO, "Application data", "Vendor uuid box " + uuid, (d.length - 16) + " bytes", b);
                }
                break;
            }
            case "free": case "skip": case "wide": {
                byte[] d = Bin.read(s.file, b, (int) Math.min(e - b, 4 << 20));
                if (!Bin.isAllZero(d, 0, d.length)) {
                    s.report.evidence(Evidence.Tier.SUPPORTING, "Hidden data", "Non-zero '" + type + "' atom", Bin.preview(d, 0, d.length, 96), b);
                    s.text.inspect("Atom " + type, "content", new String(d, StandardCharsets.ISO_8859_1), b);
                }
                break;
            }
            case "mdat":
                s.payload.add(new long[] {b, e});
                s.payloadKind = "MP4 mdat";
                break;
            case "jumb": {
                byte[] d = Bin.read(s.file, b - 8, (int) Math.min(e - b + 8, 64L << 20));
                s.c2paStore(d, b - 8, "MP4 top-level JUMBF");
                break;
            }
            default:
                if (path.startsWith("moov/udta/") && depth <= 2 && e - b < 1 << 16) {
                    byte[] d = Bin.read(s.file, b, (int) (e - b));
                    s.meta("MP4 udta", type, Bin.preview(d, 0, d.length, 160), b);
                }
        }
    }

    private void ilst(long b, long e) throws IOException {
        long p = b;
        while (p + 8 <= e) {
            byte[] h = Bin.read(s.file, p, 8);
            long size = Bin.u32be(h, 0);
            if (size < 8 || p + size > e) break;
            String item = Bin.fourcc(h, 4);
            long idx = Bin.u32be(h, 4);
            if (!keys.isEmpty() && idx >= 1 && idx <= keys.size()) item = keys.get((int) idx - 1);
            byte[] d = Bin.read(s.file, p + 8, (int) Math.min(size - 8, 32L << 20));
            String mean = "", name = "";
            int q = 0;
            while (q + 8 <= d.length) {
                int sz = (int) Bin.u32be(d, q);
                String t = Bin.fourcc(d, q + 4);
                if (sz < 8 || q + sz > d.length) break;
                if (t.equals("mean")) mean = Bin.utf8(d, q + 12, sz - 12);
                else if (t.equals("name")) name = Bin.utf8(d, q + 12, sz - 12);
                else if (t.equals("data") && sz >= 16) {
                    int kind = (int) (Bin.u32be(d, q + 8) & 0xFFFFFF);
                    byte[] v = java.util.Arrays.copyOfRange(d, q + 16, q + sz);
                    String label = item.equals("----") ? mean + ":" + name : item + " " + itemName(item);
                    value(label.trim(), item, kind, v, p);
                }
                q += sz;
            }
            p += size;
        }
    }

    private void value(String label, String item, int kind, byte[] v, long off) {
        String src = "MP4 ilst";
        if (kind == 13 || kind == 14 || item.equals("covr")) {
            s.meta(src, label, (kind == 14 ? "PNG" : kind == 13 ? "JPEG" : "image") + " " + v.length + " bytes", off);
            s.images.inspect(src + " covr", v, -1, kind == 14 ? "image/png" : "image/jpeg");
            s.report.blob("Embedded artwork (MP4 covr)", kind == 14 ? "image/png" : "image/jpeg", "artwork" + (kind == 14 ? ".png" : ".jpg"), v);
            return;
        }
        String text;
        if (kind == 1 || kind == 2 || kind == 4 || kind == 5) text = Bin.utf8(v, 0, v.length);
        else if (item.equals("trkn") || item.equals("disk")) text = v.length >= 6 ? Bin.u16be(v, 2) + "/" + Bin.u16be(v, 4) : Bin.hex(v);
        else if (kind == 21 || kind == 22 || kind == 0) {
            long n = 0;
            for (byte x : v) n = (n << 8) | (x & 0xFF);
            text = v.length <= 8 ? Long.toString(n) : Bin.preview(v, 0, v.length, 80);
            if (kind == 0) text = Bin.preview(v, 0, v.length, 120);
        } else text = Bin.preview(v, 0, v.length, 120);
        s.meta(src, label, text, off);
        if (item.equals("©too") || item.equals("©enc") || label.endsWith("iTunSMPB") || label.endsWith("Encoding Params") || label.equalsIgnoreCase("com.apple.quicktime.software")) {
            s.encoder(src, label, text, off);
            if (item.equals("©too") || label.equalsIgnoreCase("com.apple.quicktime.software")) {
                s.report.fingerprint.put("encoder", text.trim());
                s.encoderSummary = text.trim();
            }
            if (label.endsWith("iTunSMPB")) s.report.fingerprint.put("mp4.gapless", "iTunSMPB");
        }
    }

    private static String esdsInfo(byte[] d, int p, int end) {
        // Skip version/flags, then walk descriptors looking for DecoderConfigDescriptor (tag 4).
        p += 4;
        for (int i = p; i < end - 2; i++) {
            if (d[i] == 0x04) {
                int q = i + 1, len = 0;
                for (int k = 0; k < 4 && q < end; k++) { int c = d[q++] & 0xFF; len = (len << 7) | (c & 0x7F); if ((c & 0x80) == 0) break; }
                if (q + 13 > end) break;
                int oti = d[q] & 0xFF;
                long avg = Bin.u32be(d, q + 9);
                String objectType = oti == 0x40 ? "MPEG-4 Audio (AAC)" : oti == 0x6B ? "MPEG-1 Audio" : oti == 0x69 ? "MPEG-2 Audio" : String.format(Locale.ROOT, "OTI 0x%02X", oti);
                int dsi = q + 13;
                if (dsi + 2 < end && d[dsi] == 0x05) {
                    int r = dsi + 1;
                    for (int k = 0; k < 4 && r < end; k++) { int c = d[r++] & 0xFF; if ((c & 0x80) == 0) break; }
                    if (r < end) {
                        int aot = (d[r] & 0xFF) >> 3;
                        objectType += ", AOT " + aot + (aot == 2 ? " (AAC-LC)" : aot == 5 ? " (HE-AAC)" : aot == 29 ? " (HE-AACv2)" : "");
                    }
                }
                return objectType + (avg > 0 ? ", avg " + avg / 1000 + " kbps" : "");
            }
        }
        return "esds";
    }

    private static int indexOf(byte[] d, String t, int from, int to) {
        for (int i = from; i + 4 <= to; i++) if (Bin.ascii(d, i, t)) return i;
        return -1;
    }

    static String macTime(long secondsSince1904) {
        if (secondsSince1904 == 0) return "0 (not set)";
        long unix = secondsSince1904 - 2082844800L;
        Calendar c = Calendar.getInstance(TimeZone.getTimeZone("UTC"), Locale.ROOT);
        c.setTimeInMillis(unix * 1000L);
        return String.format(Locale.ROOT, "%04d-%02d-%02d %02d:%02d:%02d UTC", c.get(Calendar.YEAR), c.get(Calendar.MONTH) + 1,
                c.get(Calendar.DAY_OF_MONTH), c.get(Calendar.HOUR_OF_DAY), c.get(Calendar.MINUTE), c.get(Calendar.SECOND));
    }

    private static String itemName(String item) {
        switch (item) {
            case "©nam": return "Title";
            case "©ART": return "Artist";
            case "aART": return "Album artist";
            case "©alb": return "Album";
            case "©day": return "Date";
            case "©gen": return "Genre";
            case "©too": return "Encoding tool";
            case "©enc": return "Encoded by";
            case "©cmt": return "Comment";
            case "©lyr": return "Lyrics";
            case "©wrt": return "Composer";
            case "cprt": return "Copyright";
            case "trkn": return "Track";
            case "disk": return "Disc";
            case "tmpo": return "BPM";
            default: return "";
        }
    }
}
