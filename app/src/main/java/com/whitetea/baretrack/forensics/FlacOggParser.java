package com.whitetea.baretrack.forensics;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** FLAC metadata blocks and Ogg (Vorbis/Opus/FLAC/Speex) page and header-packet analysis. */
final class FlacOggParser {
    private FlacOggParser() {}

    // ---------------- FLAC ----------------

    static void flac(Scan s, long start, long end) throws IOException {
        ForensicReport r = s.report;
        r.container = "FLAC";
        r.node(0, "fLaC marker", start, 4, "");
        long p = start + 4;
        List<String> order = new ArrayList<>();
        boolean last = false;
        while (!last && p + 4 <= end) {
            byte[] h = Bin.read(s.file, p, 4);
            last = (h[0] & 0x80) != 0;
            int type = h[0] & 0x7F;
            int len = Bin.u24be(h, 1);
            String name = blockName(type);
            order.add(name);
            r.node(1, "Metadata block " + name, p, 4 + len, last ? "last block" : "");
            if (p + 4 + len > end) break;
            byte[] d = Bin.read(s.file, p + 4, (int) Math.min(len, 64L << 20));
            long off = p + 4;
            switch (type) {
                case 0: streamInfo(s, d, off); break;
                case 1:
                    if (!Bin.isAllZero(d, 0, d.length)) {
                        r.evidence(Evidence.Tier.SUPPORTING, "Hidden data", "Non-zero FLAC PADDING block",
                                len + " bytes; content " + Bin.preview(d, 0, d.length, 96), off);
                    }
                    s.encoder("FLAC", "Padding block", len + " bytes", off);
                    r.fingerprint.put("flac.padding", Integer.toString(len));
                    break;
                case 2: {
                    String app = Bin.fourcc(d, 0);
                    s.meta("FLAC APPLICATION", "Application ID", app + " — " + (d.length - 4) + " bytes: " + Bin.preview(d, 4, d.length - 4, 100), off);
                    int at = C2paInspector.findStore(d);
                    if (at >= 0) s.c2paStore(java.util.Arrays.copyOfRange(d, at, d.length), off + at, "FLAC APPLICATION " + app);
                    s.report.evidence(Evidence.Tier.INFO, "Application data", "FLAC APPLICATION block '" + app + "'", "", off);
                    break;
                }
                case 3: s.encoder("FLAC", "Seek table", (len / 18) + " points", off); break;
                case 4: vorbisComment(s, "FLAC Vorbis comment", d, 0, off); break;
                case 5: s.meta("FLAC", "Cue sheet", Bin.preview(d, 0, d.length, 80), off); break;
                case 6: picture(s, "FLAC PICTURE", d, off); break;
                default:
                    s.report.evidence(Evidence.Tier.INFO, "Container", "Reserved FLAC metadata block type " + type, Bin.preview(d, 0, d.length, 80), off);
            }
            p += 4 + len;
        }
        r.fingerprint.put("flac.blockOrder", Bin.join(",", order));
        s.encoder("FLAC", "Metadata block order", Bin.join(",", order), start);
        if (p < end) {
            r.node(0, "FLAC audio frames", p, end - p, "");
            s.payload.add(new long[] {p, end});
            s.payloadKind = "FLAC frames";
        }
    }

    private static void streamInfo(Scan s, byte[] d, long off) {
        if (d.length < 34) return;
        int minBlock = Bin.u16be(d, 0), maxBlock = Bin.u16be(d, 2);
        int minFrame = Bin.u24be(d, 4), maxFrame = Bin.u24be(d, 7);
        long packed = Bin.u64be(d, 10);
        int rate = (int) (packed >>> 44);
        int channels = (int) ((packed >>> 41) & 7) + 1;
        int bits = (int) ((packed >>> 36) & 31) + 1;
        long samples = packed & 0xFFFFFFFFFL;
        String md5 = Bin.hex(d, 18, 16);
        ForensicReport r = s.report;
        r.codec = String.format(Locale.ROOT, "FLAC %d Hz, %d ch, %d-bit, %d samples (%.3f s)", rate, channels, bits, samples, rate == 0 ? 0 : samples / (double) rate);
        s.declaredBits = bits;
        if (rate > 0) s.measuredDurationSec = samples / (double) rate;
        s.encoder("FLAC STREAMINFO", "Block size", minBlock + "–" + maxBlock, off);
        s.encoder("FLAC STREAMINFO", "Frame size", minFrame + "–" + maxFrame + " bytes", off);
        s.encoder("FLAC STREAMINFO", "Format", r.codec, off);
        s.encoder("FLAC STREAMINFO", "Decoded-audio MD5", md5.equals("00000000000000000000000000000000") ? "not set (writer skipped it)" : md5, off + 18);
        r.field(ForensicReport.SECTION_FILE, "FLAC", "Decoded-audio MD5 (identifies the audio regardless of tags)", md5, off + 18);
        r.fingerprint.put("flac.blocksize", minBlock + "-" + maxBlock);
        r.fingerprint.put("flac.format", rate + "/" + channels + "/" + bits);
    }

    static void vorbisComment(Scan s, String src, byte[] d, int o, long off) {
        if (o + 8 > d.length) return;
        int vlen = (int) Bin.u32le(d, o);
        if (vlen < 0 || o + 4 + vlen > d.length) return;
        String vendor = Bin.utf8(d, o + 4, vlen);
        s.encoder(src, "Vendor string", vendor, off + o + 4);
        s.report.fingerprint.put("vendor", vendor);
        s.encoderSummary = vendor;
        s.text.inspect(src, "vendor", vendor, off + o + 4);
        int p = o + 4 + vlen;
        if (p + 4 > d.length) return;
        long count = Bin.u32le(d, p);
        p += 4;
        List<String> keys = new ArrayList<>();
        for (long i = 0; i < count && p + 4 <= d.length; i++) {
            int len = (int) Bin.u32le(d, p);
            if (len < 0 || p + 4 + len > d.length) break;
            String entry = Bin.utf8(d, p + 4, len);
            int eq = entry.indexOf('=');
            String key = eq > 0 ? entry.substring(0, eq) : entry;
            String value = eq > 0 ? entry.substring(eq + 1) : "";
            keys.add(key.toUpperCase(Locale.ROOT));
            if (key.equalsIgnoreCase("METADATA_BLOCK_PICTURE")) {
                try {
                    byte[] pic = Bin.base64(value);
                    picture(s, src + " picture", pic, off + p);
                } catch (IllegalArgumentException e) {
                    s.meta(src, key, "(invalid base64)", off + p);
                }
            } else if (key.equalsIgnoreCase("COVERART")) {
                try { s.images.inspect(src + " COVERART", Bin.base64(value), -1, ""); } catch (IllegalArgumentException ignored) { }
            } else {
                s.meta(src, key, value, off + p);
                if (key.equalsIgnoreCase("ENCODER") || key.equalsIgnoreCase("ENCODED_BY") || key.equalsIgnoreCase("ENCODER_OPTIONS")) {
                    s.encoder(src, key, value, off + p);
                }
            }
            p += 4 + len;
        }
        s.report.fingerprint.put("vorbis.keys", Bin.join(",", new java.util.TreeSet<>(keys)));
    }

    static void picture(Scan s, String src, byte[] d, long off) {
        if (d.length < 32) return;
        int p = 0;
        long type = Bin.u32be(d, p); p += 4;
        int mlen = (int) Bin.u32be(d, p); p += 4;
        if (mlen < 0 || p + mlen > d.length) return;
        String mime = Bin.latin1(d, p, mlen); p += mlen;
        int dlen = (int) Bin.u32be(d, p); p += 4;
        if (dlen < 0 || p + dlen > d.length) return;
        String desc = Bin.utf8(d, p, dlen); p += dlen;
        if (p + 20 > d.length) return;
        long w = Bin.u32be(d, p), h = Bin.u32be(d, p + 4), depth = Bin.u32be(d, p + 8);
        int ilen = (int) Bin.u32be(d, p + 16);
        p += 20;
        if (ilen < 0 || p + ilen > d.length) return;
        byte[] img = java.util.Arrays.copyOfRange(d, p, p + ilen);
        s.meta(src, "Picture", "type " + type + ", " + mime + ", declared " + w + "×" + h + "×" + depth + (desc.isEmpty() ? "" : ", \"" + desc + "\""), off);
        s.images.inspect(src, img, -1, mime);
        s.report.blob("Embedded artwork (" + src + ")", mime, "artwork.img", img);
    }

    private static String blockName(int t) {
        switch (t) {
            case 0: return "STREAMINFO";
            case 1: return "PADDING";
            case 2: return "APPLICATION";
            case 3: return "SEEKTABLE";
            case 4: return "VORBIS_COMMENT";
            case 5: return "CUESHEET";
            case 6: return "PICTURE";
            default: return "RESERVED_" + t;
        }
    }

    // ---------------- Ogg ----------------

    private static int[] crcTable;

    private static int oggCrc(byte[] b) {
        if (crcTable == null) {
            int[] t = new int[256];
            for (int i = 0; i < 256; i++) {
                int r = i << 24;
                for (int k = 0; k < 8; k++) r = (r & 0x80000000) != 0 ? (r << 1) ^ 0x04C11DB7 : r << 1;
                t[i] = r;
            }
            crcTable = t;
        }
        int crc = 0;
        for (byte x : b) crc = (crc << 8) ^ crcTable[((crc >>> 24) ^ (x & 0xFF)) & 0xFF];
        return crc;
    }

    static void ogg(Scan s, long start, long end) throws IOException {
        ForensicReport r = s.report;
        r.container = "Ogg";
        Map<Long, String> codecs = new LinkedHashMap<>();
        Map<Long, List<byte[]>> packets = new HashMap<>();
        Map<Long, java.io.ByteArrayOutputStream> partial = new HashMap<>();
        Map<Long, Long> firstPage = new HashMap<>();
        Map<Long, Long> lastGranule = new HashMap<>();
        long p = start;
        int pages = 0, badCrc = 0;
        long gapBytes = 0;
        java.security.MessageDigest audioDigest;
        try { audioDigest = java.security.MessageDigest.getInstance("SHA-256"); } catch (Exception e) { audioDigest = null; }
        while (p + 27 <= end) {
            byte[] h = Bin.read(s.file, p, 27);
            if (!Bin.ascii(h, 0, "OggS")) {
                long next = findOggS(s, p + 1, end);
                long stop = next < 0 ? end : next;
                byte[] junk = Bin.read(s.file, p, (int) Math.min(stop - p, 1 << 20));
                r.node(0, "Bytes outside Ogg pages", p, stop - p, Bin.preview(junk, 0, junk.length, 64));
                if (!Bin.isAllZero(junk, 0, junk.length)) {
                    r.evidence(Evidence.Tier.SUPPORTING, "Hidden data", "Bytes outside Ogg pages", (stop - p) + " bytes: " + Bin.preview(junk, 0, junk.length, 96), p);
                }
                gapBytes += stop - p;
                if (next < 0) break;
                p = next;
                continue;
            }
            int segs = h[26] & 0xFF;
            byte[] table = Bin.read(s.file, p + 27, segs);
            int bodyLen = 0;
            for (byte b : table) bodyLen += b & 0xFF;
            int pageLen = 27 + segs + bodyLen;
            if (p + pageLen > end) break;
            byte[] page = Bin.read(s.file, p, pageLen);
            long serial = Bin.u32le(h, 14);
            long granule = Bin.u64le(h, 6);
            int stored = (int) Bin.u32le(page, 22);
            page[22] = page[23] = page[24] = page[25] = 0;
            if (oggCrc(page) != stored) badCrc++;
            if (!firstPage.containsKey(serial)) firstPage.put(serial, p);
            if (granule != 0 && granule != -1 && audioDigest != null) audioDigest.update(page, 27 + segs, bodyLen);
            if (granule != -1) lastGranule.put(serial, granule);
            // Collect the first three packets of each logical stream.
            List<byte[]> list = packets.get(serial);
            if (list == null) { list = new ArrayList<>(); packets.put(serial, list); }
            if (list.size() < 3) {
                java.io.ByteArrayOutputStream cur = partial.get(serial);
                int q = 27 + segs;
                for (int i = 0; i < segs && list.size() < 3; i++) {
                    int n = table[i] & 0xFF;
                    if (cur == null) cur = new java.io.ByteArrayOutputStream();
                    if (cur.size() < (16 << 20)) cur.write(page, q, n);
                    q += n;
                    if (n < 255) { list.add(cur.toByteArray()); cur = null; }
                }
                partial.put(serial, cur);
            }
            pages++;
            p += pageLen;
        }
        for (Map.Entry<Long, List<byte[]>> e : packets.entrySet()) {
            List<byte[]> list = e.getValue();
            if (list.isEmpty()) continue;
            String codec = identify(s, list.get(0), firstPage.get(e.getKey()));
            codecs.put(e.getKey(), codec);
            r.node(1, "Logical stream " + String.format(Locale.ROOT, "%08x", e.getKey()), firstPage.get(e.getKey()), 0, codec);
            if (list.size() > 1) {
                byte[] c = list.get(1);
                if (c.length > 7 && c[0] == 3 && Bin.ascii(c, 1, "vorbis")) vorbisComment(s, "Vorbis comment", c, 7, -1);
                else if (Bin.ascii(c, 0, "OpusTags")) vorbisComment(s, "Opus tags", c, 8, -1);
                else if (codec.startsWith("FLAC") && c.length > 4) vorbisComment(s, "Ogg FLAC comment", c, 4, -1);
                else if (codec.startsWith("Speex")) vorbisComment(s, "Speex comment", c, 0, -1);
            }
            Long g = lastGranule.get(e.getKey());
            if (g != null && s.oggRate > 0) s.measuredDurationSec = Math.max(0, g - s.oggPreSkip) / (double) s.oggRate;
        }
        r.node(0, "Ogg pages", start, p - start, pages + " pages, " + codecs.size() + " stream(s)");
        s.encoder("Ogg", "Pages", pages + " (" + badCrc + " with bad CRC)", start);
        r.fingerprint.put("ogg.streams", Bin.join("+", codecs.values()));
        if (badCrc > 0) {
            r.evidence(Evidence.Tier.SUPPORTING, "Edit history", badCrc + " Ogg page(s) fail their CRC",
                    "Page checksums are recomputed by any legitimate writer; failures mean bytes were changed in place afterwards.", start);
        }
        if (codecs.size() > 1) r.evidence(Evidence.Tier.INFO, "Container", "Multiple logical Ogg streams", codecs.values().toString(), start);
        if (audioDigest != null) {
            r.audioPayloadSha256 = Bin.hex(audioDigest.digest());
            r.audioPayloadNote = "(SHA-256 of the audio-page bodies, excluding header/comment packets and page headers — unaffected by tag changes)";
        }
        if (p < end && gapBytes == 0) {
            byte[] tail = Bin.read(s.file, p, (int) Math.min(end - p, 1 << 20));
            r.node(0, "Bytes after the last Ogg page", p, end - p, Bin.preview(tail, 0, tail.length, 64));
        }
    }

    private static String identify(Scan s, byte[] pkt, long off) {
        if (pkt.length >= 30 && pkt[0] == 1 && Bin.ascii(pkt, 1, "vorbis")) {
            int ch = pkt[11] & 0xFF;
            long rate = Bin.u32le(pkt, 12);
            long max = Bin.u32le(pkt, 16), nom = Bin.u32le(pkt, 20), min = Bin.u32le(pkt, 24);
            int blocks = pkt[28] & 0xFF;
            s.oggRate = rate;
            String c = String.format(Locale.ROOT, "Vorbis %d Hz, %d ch, nominal %d kbps (max %d, min %d), blocksizes %d/%d",
                    rate, ch, nom / 1000, (int) max / 1000, (int) min / 1000, 1 << (blocks & 15), 1 << (blocks >> 4));
            s.report.codec = c;
            s.encoder("Vorbis identification", "Format", c, off);
            s.report.fingerprint.put("vorbis.blocksizes", (1 << (blocks & 15)) + "/" + (1 << (blocks >> 4)));
            return "Vorbis";
        }
        if (pkt.length >= 19 && Bin.ascii(pkt, 0, "OpusHead")) {
            int ch = pkt[9] & 0xFF;
            int preSkip = Bin.u16le(pkt, 10);
            long inRate = Bin.u32le(pkt, 12);
            int gain = Bin.s16le(pkt, 16);
            int mapping = pkt[18] & 0xFF;
            s.oggRate = 48000;
            s.oggPreSkip = preSkip;
            String c = String.format(Locale.ROOT, "Opus v%d, %d ch, pre-skip %d, original rate %d Hz, gain %.2f dB, mapping %d",
                    pkt[8], ch, preSkip, inRate, gain / 256.0, mapping);
            s.report.codec = c;
            s.encoder("OpusHead", "Format", c, off);
            s.report.fingerprint.put("opus.preSkip", Integer.toString(preSkip));
            s.report.fingerprint.put("opus.inputRate", Long.toString(inRate));
            return "Opus";
        }
        if (pkt.length >= 13 && pkt[0] == 0x7F && Bin.ascii(pkt, 1, "FLAC")) return "FLAC-in-Ogg";
        if (pkt.length >= 8 && Bin.ascii(pkt, 0, "Speex   ")) return "Speex";
        return "unknown (" + Bin.preview(pkt, 0, pkt.length, 16) + ")";
    }

    private static long findOggS(Scan s, long from, long end) throws IOException {
        final int block = 1 << 16;
        for (long base = from; base < end; base += block - 3) {
            byte[] b = Bin.read(s.file, base, (int) Math.min(block, end - base));
            for (int i = 0; i + 4 <= b.length; i++) if (Bin.ascii(b, i, "OggS")) return base + i;
            if (b.length < block) break;
        }
        return -1;
    }
}
