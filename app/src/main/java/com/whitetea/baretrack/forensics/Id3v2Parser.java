package com.whitetea.baretrack.forensics;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.TreeSet;
import java.util.zip.Inflater;

/** Full ID3v2.2/2.3/2.4 frame decoder, including private, object, identifier, lyric and picture frames. */
final class Id3v2Parser {
    private static final int MAX_TAG = 64 * 1024 * 1024;

    private Id3v2Parser() {}

    /** @return total bytes occupied by the tag (header + body + footer), or 0 when no valid tag is at offset. */
    static long parse(Scan s, long offset, int depth, String where) throws IOException {
        byte[] h = Bin.read(s.file, offset, 10);
        if (h.length < 10 || !Bin.ascii(h, 0, "ID3")) return 0;
        int major = h[3] & 0xFF, revision = h[4] & 0xFF, flags = h[5] & 0xFF;
        if (major < 2 || major > 4 || (h[6] & 0x80) != 0 || (h[7] & 0x80) != 0 || (h[8] & 0x80) != 0 || (h[9] & 0x80) != 0) return 0;
        int size = Bin.synchsafe(h, 6);
        boolean footer = major == 4 && (flags & 0x10) != 0;
        long total = 10L + size + (footer ? 10 : 0);
        if (size > MAX_TAG || offset + 10 + size > s.length) {
            s.report.evidence(Evidence.Tier.INFO, "Container", "ID3v2 tag claims more bytes than the file holds",
                    "Declared " + size + " bytes at " + Bin.hexOffset(offset) + ".", offset);
            size = (int) Math.min(MAX_TAG, s.length - offset - 10);
            total = 10L + size;
        }
        String src = "ID3v2." + major + "." + revision + (where.isEmpty() ? "" : " (" + where + ")");
        s.report.node(depth, src + " tag", offset, total, flagText(major, flags) + ", body " + size + " B");
        byte[] body = Bin.read(s.file, offset + 10, size);
        boolean wholeUnsync = (flags & 0x80) != 0;
        if (wholeUnsync && major < 4) body = deUnsync(body, 0, body.length);
        int p = 0;
        if ((flags & 0x40) != 0 && major >= 3 && body.length >= 4) {
            int ext = major == 4 ? Bin.synchsafe(body, 0) : (int) Bin.u32be(body, 0) + 4;
            s.report.node(depth + 1, "Extended header", offset + 10, ext, "");
            p = Math.max(0, Math.min(ext, body.length));
        }
        TreeSet<String> frameSet = new TreeSet<>();
        List<String> privOwners = new ArrayList<>();
        List<String> geobTypes = new ArrayList<>();
        int frames = 0;
        int idLen = major == 2 ? 3 : 4, headLen = major == 2 ? 6 : 10;
        while (p + headLen <= body.length) {
            if (body[p] == 0) break;
            String id = Bin.latin1(body, p, idLen);
            if (!id.matches("[A-Z0-9]{3,4}")) {
                s.report.evidence(Evidence.Tier.SUPPORTING, "Hidden data", "Unparseable bytes inside the ID3v2 tag",
                        "Frame parsing stopped at tag offset " + p + " (" + Bin.preview(body, p, 32, 32) + "). "
                                + "Data placed here is invisible to normal tag readers.", offset + 10 + p);
                break;
            }
            int fsize;
            int fflags = 0;
            if (major == 2) fsize = Bin.u24be(body, p + 3);
            else {
                fsize = major == 4 ? Bin.synchsafe(body, p + 4) : (int) Bin.u32be(body, p + 4);
                // Some v2.4 writers incorrectly use plain integers; fall back when the synchsafe size overruns.
                if (major == 4 && p + headLen + fsize > body.length) fsize = (int) Bin.u32be(body, p + 4);
                fflags = Bin.u16be(body, p + 8);
            }
            int start = p + headLen;
            if (fsize < 0 || start + fsize > body.length) {
                s.report.evidence(Evidence.Tier.INFO, "Container", "ID3v2 frame " + id + " overruns the tag", "", offset + 10 + p);
                break;
            }
            long frameOffset = offset + 10 + p;
            byte[] data = new byte[fsize];
            System.arraycopy(body, start, data, 0, fsize);
            String flagNote = "";
            try {
                data = unwrapFrame(major, fflags, data, wholeUnsync);
                flagNote = frameFlagText(major, fflags);
            } catch (IOException e) {
                flagNote = "undecodable: " + e.getMessage();
                data = new byte[0];
            }
            s.report.node(depth + 1, "Frame " + id, frameOffset, headLen + fsize, flagNote);
            frameSet.add(id);
            frames++;
            try {
                decodeFrame(s, src, normalize(id), data, frameOffset, privOwners, geobTypes, depth + 2);
            } catch (RuntimeException e) {
                s.report.field(ForensicReport.SECTION_METADATA, src, id, "(malformed frame: " + e.getClass().getSimpleName() + ")", frameOffset);
            }
            p = start + fsize;
        }
        if (p < body.length) {
            int pad = body.length - p;
            boolean zero = Bin.isAllZero(body, p, pad);
            s.report.node(depth + 1, zero ? "Padding" : "Padding (non-zero!)", offset + 10 + p, pad, zero ? "" : Bin.preview(body, p, pad, 64));
            if (!zero) {
                s.report.evidence(Evidence.Tier.SUPPORTING, "Hidden data", "Non-zero bytes in ID3v2 padding",
                        pad + " bytes of padding are not zero: " + Bin.preview(body, p, pad, 80)
                                + ". Tag readers skip padding, so data here is hidden from them.", offset + 10 + p);
            }
            s.encoder(src, "Padding size", pad + " bytes", offset + 10 + p);
        }
        s.encoder(src, "Frame order", frameSetOrder(body, idLen, headLen, major), offset);
        s.report.fingerprint.putIfAbsent("id3.version", "2." + major);
        s.report.fingerprint.putIfAbsent("id3.frameSet", Bin.join(",", frameSet));
        if (!privOwners.isEmpty()) s.report.fingerprint.putIfAbsent("id3.privOwners", joinSorted(privOwners));
        if (!geobTypes.isEmpty()) s.report.fingerprint.putIfAbsent("id3.geobTypes", joinSorted(geobTypes));
        s.report.field(ForensicReport.SECTION_METADATA, src, "Frames", frames + " (" + Bin.join(", ", frameSet) + ")", offset);
        return total;
    }

    private static String joinSorted(List<String> values) {
        TreeSet<String> set = new TreeSet<>(values);
        return Bin.join(",", set);
    }

    private static String frameSetOrder(byte[] body, int idLen, int headLen, int major) {
        StringBuilder sb = new StringBuilder();
        int p = 0, count = 0;
        while (p + headLen <= body.length && body[p] != 0 && count < 200) {
            String id = Bin.latin1(body, p, idLen);
            if (!id.matches("[A-Z0-9]{3,4}")) break;
            int size = major == 2 ? Bin.u24be(body, p + 3) : major == 4 ? Bin.synchsafe(body, p + 4) : (int) Bin.u32be(body, p + 4);
            if (major == 4 && p + headLen + size > body.length) size = (int) Bin.u32be(body, p + 4);
            if (size < 0) break;
            if (sb.length() > 0) sb.append(' ');
            sb.append(id);
            p += headLen + size;
            count++;
        }
        return sb.toString();
    }

    private static String normalize(String id) {
        switch (id) {
            case "TT2": return "TIT2";
            case "TP1": return "TPE1";
            case "TP2": return "TPE2";
            case "TAL": return "TALB";
            case "TYE": return "TYER";
            case "TCO": return "TCON";
            case "TEN": return "TENC";
            case "TSS": return "TSSE";
            case "TXX": return "TXXX";
            case "COM": return "COMM";
            case "ULT": return "USLT";
            case "SLT": return "SYLT";
            case "PIC": return "PIC";
            case "GEO": return "GEOB";
            case "UFI": return "UFID";
            case "WXX": return "WXXX";
            default: return id;
        }
    }

    private static void decodeFrame(Scan s, String src, String id, byte[] d, long off, List<String> privOwners,
                                    List<String> geobTypes, int depth) throws IOException {
        if (d.length == 0) return;
        String name = frameName(id);
        String key = id + (name.isEmpty() ? "" : " " + name);
        if (id.equals("TXXX")) {
            int enc = d[0] & 0xFF;
            int[] end = new int[1];
            String desc = readString(d, 1, enc, end);
            String value = decodeText(d, end[0], d.length - end[0], enc);
            s.meta(src, "TXXX [" + desc + "]", value, off);
            String ld = desc.toLowerCase(Locale.ROOT);
            if (ld.contains("generator") || ld.contains("model") || ld.contains("ai") || ld.contains("source") || ld.contains("tool")) {
                s.report.evidence(Evidence.Tier.INFO, "Field name", "Custom TXXX field '" + desc + "'", "Value: " + Bin.clip(value, 200), off);
            }
        } else if (id.charAt(0) == 'T') {
            int enc = d[0] & 0xFF;
            String value = decodeText(d, 1, d.length - 1, enc).replace('\u0000', '/');
            while (value.endsWith("/")) value = value.substring(0, value.length() - 1);
            s.meta(src, key, value, off);
            if (id.equals("TSSE") || id.equals("TENC")) {
                s.encoder(src, key, value, off);
                s.report.fingerprint.putIfAbsent("id3.encoderTag", value);
            }
            if (id.equals("TLEN")) {
                try { s.declaredDurationSec = Long.parseLong(value.trim()) / 1000.0; } catch (NumberFormatException ignored) { }
            }
        } else if (id.equals("WXXX")) {
            int enc = d[0] & 0xFF;
            int[] end = new int[1];
            String desc = readString(d, 1, enc, end);
            s.meta(src, "WXXX [" + desc + "]", Bin.latin1(d, end[0], d.length - end[0]), off);
        } else if (id.charAt(0) == 'W') {
            s.meta(src, key, Bin.fixed(d, 0, d.length), off);
        } else if (id.equals("COMM") || id.equals("USLT")) {
            if (d.length < 4) return;
            int enc = d[0] & 0xFF;
            String lang = Bin.latin1(d, 1, 3);
            int[] end = new int[1];
            String desc = readString(d, 4, enc, end);
            String value = decodeText(d, end[0], d.length - end[0], enc);
            s.meta(src, key + " [" + lang + (desc.isEmpty() ? "" : ", " + desc) + "]", value, off);
        } else if (id.equals("SYLT")) {
            if (d.length < 6) return;
            int enc = d[0] & 0xFF;
            String lang = Bin.latin1(d, 1, 3);
            int format = d[4] & 0xFF, type = d[5] & 0xFF;
            int[] end = new int[1];
            String desc = readString(d, 6, enc, end);
            int p = end[0], lines = 0;
            StringBuilder sample = new StringBuilder();
            long lastStamp = -1;
            while (p < d.length && lines < 5000) {
                String line = readString(d, p, enc, end);
                p = end[0];
                if (p + 4 > d.length) break;
                long stamp = Bin.u32be(d, p);
                p += 4;
                if (lines < 6) sample.append(String.format(Locale.ROOT, "[%s] %s  ", format == 2 ? stamp + "ms" : stamp + "fr", line.trim()));
                lastStamp = stamp;
                lines++;
            }
            s.meta(src, "SYLT synced lyrics [" + lang + ", type " + type + (desc.isEmpty() ? "" : ", " + desc) + "]",
                    lines + " timed lines, last stamp " + lastStamp + (format == 2 ? " ms" : " frames") + ": " + sample, off);
        } else if (id.equals("APIC") || id.equals("PIC")) {
            int enc = d[0] & 0xFF;
            int p;
            String mime;
            if (id.equals("PIC")) { mime = "image/" + Bin.latin1(d, 1, 3).toLowerCase(Locale.ROOT); p = 4; }
            else {
                int z = 1;
                while (z < d.length && d[z] != 0) z++;
                mime = Bin.latin1(d, 1, z - 1);
                p = z + 1;
            }
            if (p >= d.length) return;
            int picType = d[p] & 0xFF;
            int[] end = new int[1];
            String desc = readString(d, p + 1, enc, end);
            byte[] img = new byte[Math.max(0, d.length - end[0])];
            System.arraycopy(d, end[0], img, 0, img.length);
            s.meta(src, "APIC picture", "type " + picType + " (" + pictureType(picType) + "), " + mime + (desc.isEmpty() ? "" : ", description \"" + desc + "\""), off);
            s.images.inspect(src + " APIC", img, -1, mime);
            s.report.blob("Embedded artwork (" + src + ")", mime.isEmpty() ? "image/*" : mime, "artwork" + extensionFor(img), img);
        } else if (id.equals("GEOB")) {
            int enc = d[0] & 0xFF;
            int z = 1;
            while (z < d.length && d[z] != 0) z++;
            String mime = Bin.latin1(d, 1, z - 1);
            int[] end = new int[1];
            String file = readString(d, z + 1, enc, end);
            String desc = readString(d, end[0], enc, end);
            byte[] obj = new byte[Math.max(0, d.length - end[0])];
            System.arraycopy(d, end[0], obj, 0, obj.length);
            geobTypes.add(mime);
            s.meta(src, "GEOB object", "mime \"" + mime + "\", file \"" + file + "\", description \"" + desc + "\", " + obj.length + " bytes: " + Bin.preview(obj, 0, obj.length, 120), off);
            long objOffset = off + 10 + (d.length - obj.length);
            if (mime.toLowerCase(Locale.ROOT).contains("c2pa")) {
                s.report.node(depth, "C2PA manifest store (GEOB)", objOffset, obj.length, mime);
                s.c2paStore(obj, objOffset, src + " GEOB");
            } else {
                int at = C2paInspector.findStore(obj);
                if (at >= 0) s.c2paStore(java.util.Arrays.copyOfRange(obj, at, obj.length), -1, src + " GEOB");
                else s.report.blob("GEOB object \"" + desc + "\"", mime.isEmpty() ? "application/octet-stream" : mime, file.isEmpty() ? "geob.bin" : file, obj);
            }
            inspectBinary(s, src, "GEOB", obj, off);
        } else if (id.equals("PRIV")) {
            int z = 0;
            while (z < d.length && d[z] != 0) z++;
            String owner = Bin.latin1(d, 0, z);
            byte[] priv = new byte[Math.max(0, d.length - z - 1)];
            System.arraycopy(d, Math.min(d.length, z + 1), priv, 0, priv.length);
            privOwners.add(owner);
            s.meta(src, "PRIV owner", owner, off);
            s.report.field(ForensicReport.SECTION_METADATA, src, "PRIV [" + owner + "] data", priv.length + " bytes: " + Bin.preview(priv, 0, priv.length, 200), off);
            s.report.evidence(Evidence.Tier.INFO, "Application data", "Private frame owned by '" + owner + "'",
                    "PRIV frames hold application-specific data that tag editors do not show. " + priv.length + " bytes.", off);
            inspectBinary(s, src, "PRIV [" + owner + "]", priv, off);
        } else if (id.equals("UFID")) {
            int z = 0;
            while (z < d.length && d[z] != 0) z++;
            String owner = Bin.latin1(d, 0, z);
            byte[] ident = new byte[Math.max(0, d.length - z - 1)];
            System.arraycopy(d, Math.min(d.length, z + 1), ident, 0, ident.length);
            s.meta(src, "UFID [" + owner + "]", Bin.preview(ident, 0, ident.length, 64), off);
            s.report.evidence(Evidence.Tier.INFO, "Identifier", "Unique file identifier from '" + owner + "'",
                    "Identifier " + Bin.preview(ident, 0, ident.length, 64) + ". Can be matched against the issuer's records.", off);
        } else if (id.equals("CHAP") || id.equals("CTOC")) {
            s.meta(src, key, Bin.preview(d, 0, d.length, 80), off);
        } else if (id.equals("POPM")) {
            int z = 0;
            while (z < d.length && d[z] != 0) z++;
            s.meta(src, key, Bin.latin1(d, 0, z) + " rating " + (z + 1 < d.length ? (d[z + 1] & 0xFF) : 0), off);
        } else {
            s.meta(src, key.isEmpty() ? id : key, Bin.preview(d, 0, d.length, 160), off);
        }
    }

    private static void inspectBinary(Scan s, String src, String key, byte[] data, long off) {
        if (data.length == 0) return;
        int printable = 0;
        for (byte b : data) { int c = b & 0xFF; if (c >= 0x20 && c < 0x7F || c == '\n' || c == '\t' || c == '\r') printable++; }
        if (printable > data.length * 0.8) s.text.inspect(src, key, new String(data, StandardCharsets.UTF_8), off);
        else if (data.length == 16 || data.length == 20 || data.length == 32) {
            s.report.field(ForensicReport.SECTION_STRINGS, data.length + "-byte binary value", src + " " + key, Bin.hex(data), off);
        }
    }

    private static byte[] unwrapFrame(int major, int flags, byte[] data, boolean wholeUnsync) throws IOException {
        if (major == 3) {
            boolean compressed = (flags & 0x0080) != 0, encrypted = (flags & 0x0040) != 0, grouped = (flags & 0x0020) != 0;
            int skip = (compressed ? 4 : 0) + (encrypted ? 1 : 0) + (grouped ? 1 : 0);
            if (encrypted) throw new IOException("encrypted frame");
            if (skip > data.length) throw new IOException("bad frame flags");
            byte[] body = java.util.Arrays.copyOfRange(data, skip, data.length);
            return compressed ? inflate(body) : body;
        }
        if (major == 4) {
            boolean grouped = (flags & 0x0040) != 0, compressed = (flags & 0x0008) != 0, encrypted = (flags & 0x0004) != 0;
            boolean unsync = (flags & 0x0002) != 0 || wholeUnsync, lengthIndicator = (flags & 0x0001) != 0;
            int skip = (grouped ? 1 : 0) + (encrypted ? 1 : 0) + (lengthIndicator ? 4 : 0);
            if (encrypted) throw new IOException("encrypted frame");
            if (skip > data.length) throw new IOException("bad frame flags");
            byte[] body = java.util.Arrays.copyOfRange(data, skip, data.length);
            if (unsync) body = deUnsync(body, 0, body.length);
            return compressed ? inflate(body) : body;
        }
        return data;
    }

    private static String frameFlagText(int major, int flags) {
        if (major < 3 || flags == 0) return "";
        List<String> f = new ArrayList<>();
        if (major == 3) {
            if ((flags & 0x0080) != 0) f.add("zlib-compressed");
            if ((flags & 0x0040) != 0) f.add("encrypted");
            if ((flags & 0x0020) != 0) f.add("grouped");
            if ((flags & 0x8000) != 0) f.add("discard-on-tag-alter");
            if ((flags & 0x2000) != 0) f.add("read-only");
        } else {
            if ((flags & 0x0008) != 0) f.add("zlib-compressed");
            if ((flags & 0x0004) != 0) f.add("encrypted");
            if ((flags & 0x0040) != 0) f.add("grouped");
            if ((flags & 0x0002) != 0) f.add("unsynchronised");
            if ((flags & 0x1000) != 0) f.add("read-only");
        }
        return Bin.join(", ", f);
    }

    private static String flagText(int major, int flags) {
        List<String> f = new ArrayList<>();
        if ((flags & 0x80) != 0) f.add("unsynchronised");
        if ((flags & 0x40) != 0) f.add(major == 2 ? "compressed" : "extended header");
        if ((flags & 0x20) != 0) f.add("experimental");
        if ((flags & 0x10) != 0 && major == 4) f.add("footer");
        return f.isEmpty() ? "no flags" : Bin.join(", ", f);
    }

    private static byte[] inflate(byte[] in) throws IOException {
        Inflater inf = new Inflater();
        try {
            inf.setInput(in);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            while (!inf.finished()) {
                int n = inf.inflate(buf);
                if (n == 0 && (inf.needsInput() || inf.needsDictionary())) break;
                out.write(buf, 0, n);
                if (out.size() > MAX_TAG) throw new IOException("compressed frame too large");
            }
            return out.toByteArray();
        } catch (java.util.zip.DataFormatException e) {
            throw new IOException("bad zlib data");
        } finally {
            inf.end();
        }
    }

    static byte[] deUnsync(byte[] in, int o, int n) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(n);
        for (int i = o; i < o + n; i++) {
            out.write(in[i]);
            if ((in[i] & 0xFF) == 0xFF && i + 1 < o + n && in[i + 1] == 0) i++;
        }
        return out.toByteArray();
    }

    private static Charset charset(int enc) {
        switch (enc) {
            case 1: return StandardCharsets.UTF_16;
            case 2: return StandardCharsets.UTF_16BE;
            case 3: return StandardCharsets.UTF_8;
            default: return StandardCharsets.ISO_8859_1;
        }
    }

    static String decodeText(byte[] d, int o, int n, int enc) {
        if (n <= 0 || o >= d.length) return "";
        n = Math.min(n, d.length - o);
        String s = new String(d, o, n, charset(enc));
        int end = s.length();
        while (end > 0 && s.charAt(end - 1) == 0) end--;
        return s.substring(0, end);
    }

    /** Read a NUL-terminated string in the given encoding; end[0] receives the index after the terminator. */
    static String readString(byte[] d, int o, int enc, int[] end) {
        boolean wide = enc == 1 || enc == 2;
        int i = o;
        if (wide) {
            while (i + 1 < d.length && !(d[i] == 0 && d[i + 1] == 0)) i += 2;
            end[0] = Math.min(d.length, i + 2);
        } else {
            while (i < d.length && d[i] != 0) i++;
            end[0] = Math.min(d.length, i + 1);
        }
        return decodeText(d, o, i - o, enc);
    }

    private static String extensionFor(byte[] img) {
        if (img.length > 3 && (img[0] & 0xFF) == 0xFF && (img[1] & 0xFF) == 0xD8) return ".jpg";
        if (img.length > 8 && Bin.ascii(img, 1, "PNG")) return ".png";
        return ".img";
    }

    private static String pictureType(int t) {
        String[] names = {"other", "32x32 icon", "other icon", "front cover", "back cover", "leaflet", "media", "lead artist",
                "artist", "conductor", "band", "composer", "lyricist", "recording location", "during recording",
                "during performance", "screen capture", "bright fish", "illustration", "band logo", "publisher logo"};
        return t < names.length ? names[t] : "unknown";
    }

    static String frameName(String id) {
        switch (id) {
            case "TIT2": return "Title";
            case "TPE1": return "Artist";
            case "TPE2": return "Album artist";
            case "TALB": return "Album";
            case "TYER": return "Year";
            case "TDRC": return "Recording time";
            case "TDEN": return "Encoding time";
            case "TDTG": return "Tagging time";
            case "TCON": return "Genre";
            case "TRCK": return "Track";
            case "TPOS": return "Disc";
            case "TCOM": return "Composer";
            case "TEXT": return "Lyricist";
            case "TPUB": return "Publisher";
            case "TCOP": return "Copyright";
            case "TENC": return "Encoded by";
            case "TSSE": return "Encoder settings/software";
            case "TLEN": return "Length (ms)";
            case "TBPM": return "BPM";
            case "TKEY": return "Key";
            case "TSRC": return "ISRC";
            case "TMED": return "Media type";
            case "TFLT": return "File type";
            case "TOFN": return "Original filename";
            case "TOWN": return "File owner";
            case "TPE3": return "Conductor";
            case "TPE4": return "Remixer";
            case "TIT1": return "Content group";
            case "TIT3": return "Subtitle";
            case "TLAN": return "Language";
            case "TMOO": return "Mood";
            case "TSOT": return "Title sort";
            case "TSOP": return "Artist sort";
            case "COMM": return "Comment";
            case "USLT": return "Lyrics";
            case "WOAR": return "Artist URL";
            case "WOAS": return "Source URL";
            case "WOAF": return "File URL";
            case "WCOM": return "Commercial URL";
            case "WPUB": return "Publisher URL";
            case "MCDI": return "CD identifier";
            case "POPM": return "Popularimeter";
            case "PCNT": return "Play counter";
            default: return "";
        }
    }
}
