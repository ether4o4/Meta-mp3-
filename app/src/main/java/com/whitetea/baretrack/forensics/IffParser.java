package com.whitetea.baretrack.forensics;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** RIFF/WAVE (incl. RF64, BW64, RIFX) and IFF FORM/AIFF/AIFC chunk dissection. */
final class IffParser {
    private static final Pattern XML_TAG = Pattern.compile("<([A-Za-z_][\\w:.-]{0,60})>([^<]{1,300})</\\1>");

    private IffParser() {}

    static void parse(Scan s, long start, long end) throws IOException {
        byte[] h = Bin.read(s.file, start, 12);
        String form = Bin.fourcc(h, 0);
        boolean aiff = form.equals("FORM");
        boolean bigEndian = aiff || form.equals("RIFX");
        long declared = bigEndian ? Bin.u32be(h, 4) : Bin.u32le(h, 4);
        String kind = Bin.fourcc(h, 8);
        ForensicReport r = s.report;
        r.container = aiff ? (kind.equals("AIFC") ? "AIFF-C" : "AIFF") : form + "/" + kind;
        long ds64Riff = -1, ds64Data = -1;
        long containerEnd = start + 8 + declared;
        if (form.equals("RF64") || form.equals("BW64")) containerEnd = end;
        r.node(0, form + " " + kind + " container", start, Math.min(end, containerEnd) - start, "declared size " + declared);

        List<String> order = new ArrayList<>();
        long p = start + 12;
        long limit = Math.min(end, containerEnd);
        while (p + 8 <= limit) {
            byte[] ch = Bin.read(s.file, p, 8);
            String id = Bin.fourcc(ch, 0);
            long size = bigEndian ? Bin.u32be(ch, 4) : Bin.u32le(ch, 4);
            if (!id.matches("[ -~]{4}")) {
                r.evidence(Evidence.Tier.SUPPORTING, "Container", "Chunk walk stopped at unreadable bytes",
                        Bin.preview(Bin.read(s.file, p, 32), 0, 32, 32), p);
                break;
            }
            if (size == 0xFFFFFFFFL && id.equals("data") && ds64Data >= 0) size = ds64Data;
            long bodyStart = p + 8;
            boolean overrun = bodyStart + size > limit;
            long body = overrun ? limit - bodyStart : size;
            order.add(id.trim());
            String note = overrun ? "declared " + size + " B — runs past the container end" : "";
            r.node(1, "Chunk '" + id + "'", p, 8 + body, note);
            if (overrun) {
                r.evidence(Evidence.Tier.INFO, "Container", "Chunk '" + id + "' size exceeds the container", note, p);
            }
            try {
                chunk(s, id, bodyStart, body, aiff, bigEndian);
                if (id.equals("ds64") && body >= 24) {
                    byte[] d = Bin.read(s.file, bodyStart, 24);
                    ds64Riff = Bin.u64le(d, 0);
                    ds64Data = Bin.u64le(d, 8);
                    s.encoder("ds64", "64-bit sizes", "RIFF " + ds64Riff + ", data " + ds64Data + ", samples " + Bin.u64le(d, 16), bodyStart);
                    if (form.equals("RF64") || form.equals("BW64")) limit = Math.min(end, start + 8 + ds64Riff);
                }
            } catch (RuntimeException e) {
                r.field(ForensicReport.SECTION_METADATA, "Chunk " + id, "Parse error", e.getClass().getSimpleName(), bodyStart);
            }
            long next = bodyStart + body + (body % 2);
            if (next <= p) break;
            p = next;
        }
        String chunkOrder = Bin.join(",", order);
        s.encoder(r.container, "Chunk order", chunkOrder, start);
        r.fingerprint.put(aiff ? "aiff.chunkOrder" : "riff.chunkOrder", chunkOrder);
        if (!aiff && declared + 8 != end - start && !form.equals("RF64") && !form.equals("BW64")) {
            long diff = (end - start) - (declared + 8);
            if (diff > 0) {
                byte[] tail = Bin.read(s.file, start + 8 + declared, (int) Math.min(diff, 4 * 1024 * 1024));
                r.node(0, "Bytes after the RIFF container", start + 8 + declared, diff, Bin.preview(tail, 0, tail.length, 64));
                if (!Bin.isAllZero(tail, 0, tail.length)) {
                    r.evidence(Evidence.Tier.SUPPORTING, "Hidden data", "Data appended after the RIFF container",
                            diff + " bytes after the declared end; WAV readers ignore them. " + Bin.preview(tail, 0, tail.length, 96), start + 8 + declared);
                    int at = C2paInspector.findStore(tail);
                    if (at >= 0) s.c2paStore(java.util.Arrays.copyOfRange(tail, at, tail.length), start + 8 + declared + at, "after RIFF");
                    s.report.blob("Bytes after RIFF", "application/octet-stream", "after_riff.bin", tail);
                }
            } else {
                r.evidence(Evidence.Tier.INFO, "Container", "RIFF size field is larger than the file",
                        "Declared " + (declared + 8) + " bytes, file holds " + (end - start) + ". The file was truncated or the header was not finalised.", start + 4);
            }
        }
    }

    private static void chunk(Scan s, String id, long off, long size, boolean aiff, boolean be) throws IOException {
        ForensicReport r = s.report;
        String src = "Chunk " + id.trim();
        switch (id) {
            case "fmt ": {
                byte[] d = Bin.read(s.file, off, (int) Math.min(size, 4096));
                if (d.length < 16) return;
                int tag = Bin.u16le(d, 0), ch = Bin.u16le(d, 2), bits = Bin.u16le(d, 14), align = Bin.u16le(d, 12);
                long rate = Bin.u32le(d, 4), byteRate = Bin.u32le(d, 8);
                String fmt = formatTag(tag);
                StringBuilder sb = new StringBuilder(String.format(Locale.ROOT, "%s, %d ch, %d Hz, %d-bit, block align %d, %d B/s", fmt, ch, rate, bits, align, byteRate));
                if (tag == 0xFFFE && d.length >= 40) {
                    int valid = Bin.u16le(d, 18);
                    long mask = Bin.u32le(d, 20);
                    int sub = Bin.u16le(d, 24);
                    sb.append(String.format(Locale.ROOT, "; extensible: %d valid bits, channel mask 0x%X, subformat %s (GUID %s)", valid, mask, formatTag(sub), Bin.hex(d, 24, 16)));
                    if (valid != 0 && valid < bits) s.declaredBits = valid;
                }
                if (d.length > 16) sb.append("; cbSize ").append(d.length >= 18 ? Bin.u16le(d, 16) : 0).append(", fmt chunk ").append(size).append(" B");
                r.codec = sb.toString();
                if (s.declaredBits == 0) s.declaredBits = bits;
                s.encoder("fmt", "Format", sb.toString(), off);
                r.fingerprint.put("wav.format", fmt + " " + bits + "-bit " + ch + "ch " + rate);
                r.fingerprint.put("wav.fmtSize", Long.toString(size));
                if (byteRate != rate * align) {
                    r.evidence(Evidence.Tier.INFO, "Container", "WAV byte rate is inconsistent", "byteRate " + byteRate + " ≠ rate × blockAlign " + rate * align, off);
                }
                break;
            }
            case "data":
                s.payload.add(new long[] {off, off + size});
                s.payloadKind = "WAV data chunk";
                break;
            case "LIST": {
                byte[] d = Bin.read(s.file, off, (int) Math.min(size, 1 << 20));
                if (d.length < 4) return;
                String type = Bin.fourcc(d, 0);
                int p = 4;
                while (p + 8 <= d.length) {
                    String sub = Bin.fourcc(d, p);
                    int n = (int) Bin.u32le(d, p + 4);
                    if (n < 0 || p + 8 + n > d.length) break;
                    String value = Bin.fixed(d, p + 8, n);
                    if (type.equals("INFO")) {
                        s.meta("RIFF LIST INFO", sub + " " + infoName(sub), value, off + p);
                        if (sub.equals("ISFT")) {
                            s.encoder("RIFF LIST INFO", "ISFT software", value, off + p);
                            r.fingerprint.put("encoder", value);
                            s.encoderSummary = value;
                        }
                    } else if (type.equals("adtl")) {
                        s.meta("RIFF LIST adtl", sub, Bin.preview(d, p + 8, n, 80), off + p);
                    } else {
                        s.meta("RIFF LIST " + type, sub, Bin.preview(d, p + 8, n, 120), off + p);
                    }
                    p += 8 + n + (n % 2);
                }
                break;
            }
            case "bext": {
                byte[] d = Bin.read(s.file, off, (int) Math.min(size, 1 << 20));
                if (d.length < 346) return;
                String b = "BWF bext";
                s.meta(b, "Description", Bin.fixed(d, 0, 256), off);
                s.meta(b, "Originator", Bin.fixed(d, 256, 32), off + 256);
                s.meta(b, "OriginatorReference", Bin.fixed(d, 288, 32), off + 288);
                s.meta(b, "OriginationDate", Bin.fixed(d, 320, 10), off + 320);
                s.meta(b, "OriginationTime", Bin.fixed(d, 330, 8), off + 330);
                s.meta(b, "TimeReference (samples)", Long.toString(Bin.u64le(d, 338)), off + 338);
                int version = Bin.u16le(d, 346);
                s.meta(b, "Version", Integer.toString(version), off + 346);
                if (d.length >= 412 && !Bin.isAllZero(d, 348, 64)) s.meta(b, "UMID", Bin.hex(d, 348, 64), off + 348);
                if (version >= 2 && d.length >= 422) {
                    s.meta(b, "Loudness", String.format(Locale.ROOT, "integrated %.2f LUFS, range %.2f LU, true peak %.2f dBTP",
                            Bin.s16le(d, 412) / 100.0, Bin.s16le(d, 414) / 100.0, Bin.s16le(d, 416) / 100.0), off + 412);
                }
                if (d.length > 602) {
                    String history = Bin.latin1(d, 602, d.length - 602).replace('\u0000', ' ').trim();
                    s.meta(b, "CodingHistory", history, off + 602);
                    s.encoder(b, "CodingHistory", history, off + 602);
                }
                String originator = Bin.fixed(d, 256, 32);
                if (!originator.isEmpty()) {
                    s.encoder(b, "Originator", originator, off + 256);
                    r.fingerprint.put("bext.originator", originator);
                }
                break;
            }
            case "iXML": case "axml": case "_PMX": case "XMP ": {
                byte[] d = Bin.read(s.file, off, (int) Math.min(size, 4 << 20));
                String xml = new String(d, StandardCharsets.UTF_8);
                String label = id.equals("_PMX") || id.equals("XMP ") ? "XMP" : id;
                if (label.equals("XMP")) s.images.xmp("RIFF " + id.trim(), xml, off);
                else {
                    Matcher m = XML_TAG.matcher(xml);
                    int n = 0;
                    while (m.find() && n++ < 120) s.meta(label, m.group(1), m.group(2).trim(), off);
                    s.text.inspect(label, "document", xml, off);
                }
                r.field(ForensicReport.SECTION_METADATA, label, "Raw XML", Bin.clip(xml.trim(), 1500), off);
                break;
            }
            case "id3 ": case "ID3 ": case "ID32":
                Id3v2Parser.parse(s, off, 2, "inside " + id.trim() + " chunk");
                break;
            case "C2PA": case "c2pa": {
                byte[] d = Bin.read(s.file, off, (int) Math.min(size, 64 << 20));
                r.node(2, "C2PA manifest store", off, size, "");
                s.c2paStore(d, off, "RIFF C2PA chunk");
                break;
            }
            case "cue ": {
                byte[] d = Bin.read(s.file, off, (int) Math.min(size, 1 << 16));
                if (d.length >= 4) s.meta("cue", "Cue points", Long.toString(Bin.u32le(d, 0)), off);
                break;
            }
            case "smpl": {
                byte[] d = Bin.read(s.file, off, (int) Math.min(size, 1 << 16));
                if (d.length >= 36) s.meta("smpl", "Sampler data", "manufacturer " + Bin.u32le(d, 0) + ", product " + Bin.u32le(d, 4)
                        + ", root note " + Bin.u32le(d, 12) + ", loops " + Bin.u32le(d, 28), off);
                break;
            }
            case "acid": {
                byte[] d = Bin.read(s.file, off, (int) Math.min(size, 64));
                if (d.length >= 24) s.meta("acid", "ACID loop info", String.format(Locale.ROOT, "flags 0x%X, root %d, beats %d, tempo %.2f",
                        Bin.u32le(d, 0), Bin.u16le(d, 4), Bin.u32le(d, 12), Float.intBitsToFloat((int) Bin.u32le(d, 20))), off);
                break;
            }
            case "fact": {
                byte[] d = Bin.read(s.file, off, 4);
                if (d.length == 4) s.meta("fact", "Sample frames", Long.toString(Bin.u32le(d, 0)), off);
                break;
            }
            case "JUNK": case "junk": case "PAD ": case "FLLR": case "free": {
                byte[] d = Bin.read(s.file, off, (int) Math.min(size, 4 << 20));
                if (!Bin.isAllZero(d, 0, d.length)) {
                    r.evidence(Evidence.Tier.SUPPORTING, "Hidden data", "Non-zero bytes in '" + id + "' padding chunk",
                            "Padding chunks are skipped by readers. Content: " + Bin.preview(d, 0, d.length, 96), off);
                    s.text.inspect("Chunk " + id, "content", new String(d, StandardCharsets.ISO_8859_1), off);
                }
                break;
            }
            // ---- AIFF ----
            case "COMM": {
                if (!aiff) { unknown(s, id, off, size); break; }
                byte[] d = Bin.read(s.file, off, (int) Math.min(size, 256));
                if (d.length < 18) return;
                int ch = Bin.u16be(d, 0);
                long frames = Bin.u32be(d, 2);
                int bits = Bin.u16be(d, 6);
                double rate = extended(d, 8);
                String comp = d.length >= 22 ? Bin.fourcc(d, 18) : "NONE";
                String compName = d.length > 23 ? Bin.latin1(d, 23, d[22] & 0xFF) : "";
                r.codec = String.format(Locale.ROOT, "%d ch, %.0f Hz, %d-bit, %d frames, compression %s %s", ch, rate, bits, frames, comp, compName).trim();
                s.declaredBits = bits;
                s.encoder("COMM", "Format", r.codec, off);
                r.fingerprint.put("aiff.format", comp + " " + bits + "-bit " + ch + "ch " + Math.round(rate));
                break;
            }
            case "SSND": {
                byte[] d = Bin.read(s.file, off, 8);
                long o = d.length >= 4 ? Bin.u32be(d, 0) : 0;
                s.payload.add(new long[] {off + 8 + o, off + size});
                s.payloadKind = "AIFF SSND samples";
                break;
            }
            case "NAME": case "AUTH": case "(c) ": case "ANNO": {
                byte[] d = Bin.read(s.file, off, (int) Math.min(size, 1 << 16));
                s.meta("AIFF " + id.trim(), id.equals("NAME") ? "Name" : id.equals("AUTH") ? "Author" : id.equals("ANNO") ? "Annotation" : "Copyright",
                        Bin.fixed(d, 0, d.length), off);
                break;
            }
            case "APPL": {
                byte[] d = Bin.read(s.file, off, (int) Math.min(size, 1 << 16));
                if (d.length >= 4) {
                    s.meta("AIFF APPL", "Application signature", Bin.fourcc(d, 0) + " (" + (d.length - 4) + " bytes: " + Bin.preview(d, 4, d.length - 4, 80) + ")", off);
                    s.encoder("AIFF APPL", "Application", Bin.fourcc(d, 0), off);
                }
                break;
            }
            case "COMT": {
                byte[] d = Bin.read(s.file, off, (int) Math.min(size, 1 << 16));
                if (d.length < 2) return;
                int n = Bin.u16be(d, 0), p = 2;
                for (int i = 0; i < n && p + 8 <= d.length; i++) {
                    int len = Bin.u16be(d, p + 6);
                    s.meta("AIFF COMT", "Comment (timestamp " + Bin.u32be(d, p) + ")", Bin.latin1(d, p + 8, len), off + p);
                    p += 8 + len + (len % 2);
                }
                break;
            }
            case "FVER": case "MARK": case "INST": case "ds64":
                break;
            default:
                unknown(s, id, off, size);
        }
    }

    private static void unknown(Scan s, String id, long off, long size) throws IOException {
        byte[] d = Bin.read(s.file, off, (int) Math.min(size, 1 << 16));
        String hint = producerHint(id);
        s.meta("Chunk " + id.trim(), "Content", Bin.preview(d, 0, d.length, 120), off);
        if (hint != null) {
            s.encoder("Chunk " + id.trim(), "Typical producer", hint, off);
            s.report.evidence(Evidence.Tier.SUPPORTING, "Export pipeline", "'" + id + "' chunk — " + hint,
                    "Application-specific chunk; indicates which software last wrote the file.", off);
        } else {
            s.report.evidence(Evidence.Tier.INFO, "Container", "Unrecognised chunk '" + id + "' (" + size + " B)", Bin.preview(d, 0, d.length, 80), off);
        }
        int printable = 0;
        for (byte b : d) { int c = b & 0xFF; if (c >= 0x20 && c < 0x7F) printable++; }
        if (printable > d.length * 0.6) s.text.inspect("Chunk " + id.trim(), "content", new String(d, StandardCharsets.UTF_8), off);
        int at = C2paInspector.findStore(d);
        if (at >= 0) s.c2paStore(java.util.Arrays.copyOfRange(d, at, d.length), off + at, "chunk " + id.trim());
    }

    private static String producerHint(String id) {
        switch (id) {
            case "LGWV": case "ResU": return "commonly written by Apple Logic Pro";
            case "minf": case "elm1": case "regn": case "umid": return "commonly written by Avid Pro Tools";
            case "PEAK": return "peak-envelope chunk (Adobe Audition and broadcast tools)";
            case "cart": return "broadcast CART chunk (radio automation)";
            case "SyLp": return "commonly written by Sony/Magix Sound Forge";
            case "DISP": return "Windows/legacy display chunk";
            case "inst": return "sampler instrument chunk";
            case "levl": return "EBU level chunk (broadcast tools)";
            case "MLVL": return "loudness chunk";
            case "strc": case "cdif": return "commonly written by ACID/Vegas";
            case "Fake": return "padding chunk written by some Apple tools";
            default: return null;
        }
    }

    private static String formatTag(int tag) {
        switch (tag) {
            case 0x0001: return "PCM";
            case 0x0002: return "MS ADPCM";
            case 0x0003: return "IEEE float";
            case 0x0006: return "A-law";
            case 0x0007: return "µ-law";
            case 0x0011: return "IMA ADPCM";
            case 0x0055: return "MPEG Layer III";
            case 0xFFFE: return "WAVE_FORMAT_EXTENSIBLE";
            default: return String.format(Locale.ROOT, "0x%04X", tag);
        }
    }

    private static String infoName(String id) {
        switch (id) {
            case "INAM": return "Title";
            case "IART": return "Artist";
            case "IPRD": return "Album/product";
            case "ICMT": return "Comment";
            case "ICRD": return "Creation date";
            case "IGNR": return "Genre";
            case "ISFT": return "Software";
            case "IENG": return "Engineer";
            case "ITCH": return "Technician";
            case "ICOP": return "Copyright";
            case "ISRC": return "Source";
            case "ISBJ": return "Subject";
            case "IKEY": return "Keywords";
            case "ITRK": case "IPRT": return "Track";
            default: return "";
        }
    }

    /** IEEE 754 80-bit extended (AIFF sample rate). */
    static double extended(byte[] b, int o) {
        int exp = ((b[o] & 0x7F) << 8) | (b[o + 1] & 0xFF);
        long mant = Bin.u64be(b, o + 2);
        if (exp == 0 && mant == 0) return 0;
        double m = (mant >>> 11) / (double) (1L << 52);
        double v = m * Math.pow(2, exp - 16383);
        return (b[o] & 0x80) != 0 ? -v : v;
    }
}
