package com.whitetea.baretrack.forensics;

import java.io.IOException;
import java.security.MessageDigest;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;

/** Frame-level MPEG audio walk: stream statistics, Xing/Info/LAME/VBRI headers, bit reservoir, gaps. */
final class MpegStreamParser {
    private static final int[][] BITRATES = {
            {0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448, 0},   // V1 L1
            {0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384, 0},      // V1 L2
            {0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0},       // V1 L3
            {0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256, 0},      // V2 L1
            {0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0},           // V2 L2/L3
    };
    private static final int[] RATES = {44100, 48000, 32000};
    private static final String[] MODES = {"stereo", "joint stereo", "dual channel", "mono"};

    static final class Header {
        int version;   // 3 = MPEG1, 2 = MPEG2, 0 = MPEG2.5
        int layer;     // 1..3
        int bitrate;
        int sampleRate;
        int padding;
        int mode;
        int modeExt;
        boolean crc;
        boolean privateBit;
        boolean copyright;
        boolean original;
        int emphasis;
        int length;
        int samples;

        String versionName() { return version == 3 ? "MPEG-1" : version == 2 ? "MPEG-2" : "MPEG-2.5"; }
        int sideInfo() { return version == 3 ? (mode == 3 ? 17 : 32) : (mode == 3 ? 9 : 17); }
    }

    /** Sliding read window so large streams are not loaded whole. */
    private static final class Window {
        final Scan s;
        byte[] buf = new byte[0];
        long base = -1;
        Window(Scan s) { this.s = s; }

        byte[] get(long off, int n) throws IOException {
            if (base < 0 || off < base || off + n > base + buf.length) {
                base = off;
                buf = Bin.read(s.file, off, Math.max(n, 1 << 20));
            }
            if (off + n > base + buf.length) return null;
            byte[] out = new byte[n];
            System.arraycopy(buf, (int) (off - base), out, 0, n);
            return out;
        }

        int u8(long off) throws IOException {
            byte[] b = get(off, 1);
            return b == null ? -1 : b[0] & 0xFF;
        }
    }

    private MpegStreamParser() {}

    static Header header(byte[] b, int o) {
        if (o + 4 > b.length) return null;
        int b0 = b[o] & 0xFF, b1 = b[o + 1] & 0xFF, b2 = b[o + 2] & 0xFF, b3 = b[o + 3] & 0xFF;
        if (b0 != 0xFF || (b1 & 0xE0) != 0xE0) return null;
        Header h = new Header();
        h.version = (b1 >> 3) & 3;
        int layerBits = (b1 >> 1) & 3;
        int br = (b2 >> 4) & 0xF, sr = (b2 >> 2) & 3;
        if (h.version == 1 || layerBits == 0 || br == 0 || br == 15 || sr == 3) return null;
        h.layer = 4 - layerBits;
        h.crc = (b1 & 1) == 0;
        int table = h.version == 3 ? h.layer - 1 : (h.layer == 1 ? 3 : 4);
        h.bitrate = BITRATES[table][br];
        h.sampleRate = RATES[sr] >> (h.version == 3 ? 0 : h.version == 2 ? 1 : 2);
        h.padding = (b2 >> 1) & 1;
        h.privateBit = (b2 & 1) != 0;
        h.mode = (b3 >> 6) & 3;
        h.modeExt = (b3 >> 4) & 3;
        h.copyright = (b3 & 8) != 0;
        h.original = (b3 & 4) != 0;
        h.emphasis = b3 & 3;
        if (h.layer == 1) {
            h.length = (12 * h.bitrate * 1000 / h.sampleRate + h.padding) * 4;
            h.samples = 384;
        } else if (h.layer == 2 || h.version == 3) {
            h.length = 144 * h.bitrate * 1000 / h.sampleRate + h.padding;
            h.samples = 1152;
        } else {
            h.length = 72 * h.bitrate * 1000 / h.sampleRate + h.padding;
            h.samples = 576;
        }
        if (h.length < 21 || h.length > 8192) return null;
        return h;
    }

    private static Header at(Window w, long off, long end) throws IOException {
        if (off + 4 > end) return null;
        byte[] b = w.get(off, 4);
        if (b == null) return null;
        Header h = header(b, 0);
        if (h == null || off + h.length > end) return null;
        return h;
    }

    private static boolean compatible(Header a, Header b) {
        return a.version == b.version && a.layer == b.layer && a.sampleRate == b.sampleRate;
    }

    /** Find a frame followed by a compatible frame (or the end of the region). */
    static long sync(Window w, long from, long end) throws IOException {
        for (long off = from; off + 4 <= end; off++) {
            int c = w.u8(off);
            if (c != 0xFF) continue;
            Header h = at(w, off, end);
            if (h == null) continue;
            long next = off + h.length;
            if (next == end) return off;
            Header n = at(w, next, end);
            if (n != null && compatible(h, n)) return off;
        }
        return -1;
    }

    static boolean looksLikeMpeg(Scan s, long start, long end) throws IOException {
        Window w = new Window(s);
        long first = sync(w, start, Math.min(end, start + 128 * 1024));
        return first >= 0;
    }

    static void parse(Scan s, long start, long end) throws IOException {
        Window w = new Window(s);
        ForensicReport r = s.report;
        long first = sync(w, start, end);
        if (first < 0) {
            r.evidence(Evidence.Tier.INFO, "Container", "No MPEG audio frames found", "", start);
            return;
        }
        if (first > start) gap(s, w, start, first, "Bytes before the first audio frame");

        MessageDigest payload;
        try { payload = MessageDigest.getInstance("SHA-256"); } catch (Exception e) { payload = null; }
        long pos = first, runStart = first, gapBytes = 0;
        int frames = 0, gaps = 0, crcFrames = 0, padded = 0, privateBits = 0, copyrightBits = 0, originalBits = 0;
        long reservoirSum = 0;
        int reservoirMax = 0, reservoirZero = 0, reservoirFrames = 0;
        long totalSamples = 0, audioBytes = 0;
        Map<Integer, Integer> bitrates = new TreeMap<>();
        Map<String, Integer> modes = new TreeMap<>();
        Map<String, Integer> modeExt = new TreeMap<>();
        Map<Integer, Integer> emphasis = new TreeMap<>();
        Header firstHeader = null, last = null;
        boolean infoFrame = false;
        long infoFrameOffset = -1;
        String formats = "";

        while (pos + 4 <= end) {
            Header h = at(w, pos, end);
            if (h != null && last != null && !compatible(h, last)) h = null;
            if (h == null) {
                long next = sync(w, pos + 1, end);
                if (pos > runStart) r.node(0, "MPEG audio frames", runStart, pos - runStart, "");
                long gapEnd = next < 0 ? end : next;
                gap(s, w, pos, gapEnd, next < 0 ? "Bytes after the last audio frame" : "Bytes between audio frames");
                gaps++;
                gapBytes += gapEnd - pos;
                if (next < 0) { pos = end; runStart = end; break; }
                pos = next;
                runStart = next;
                continue;
            }
            byte[] frame = w.get(pos, h.length);
            if (frame == null) break;
            if (frames == 0) {
                firstHeader = h;
                formats = h.versionName() + " Layer " + roman(h.layer);
                infoFrame = encoderHeaders(s, frame, h, pos);
                if (infoFrame) infoFrameOffset = pos;
            }
            if (!(frames == 0 && infoFrame)) {
                if (payload != null) payload.update(frame);
                audioBytes += h.length;
                totalSamples += h.samples;
                bitrates.put(h.bitrate, (bitrates.containsKey(h.bitrate) ? bitrates.get(h.bitrate) : 0) + 1);
                inc(modes, MODES[h.mode]);
                if (h.layer == 3 && h.mode == 1) inc(modeExt, ((h.modeExt & 2) != 0 ? "MS" : "noMS") + "+" + ((h.modeExt & 1) != 0 ? "IS" : "noIS"));
                inc(emphasis, h.emphasis);
                if (h.crc) crcFrames++;
                if (h.padding == 1) padded++;
                if (h.privateBit) privateBits++;
                if (h.copyright) copyrightBits++;
                if (h.original) originalBits++;
                if (h.layer == 3) {
                    int o = 4 + (h.crc ? 2 : 0);
                    int mdb = h.version == 3 ? ((frame[o] & 0xFF) << 1) | ((frame[o + 1] & 0xFF) >> 7) : frame[o] & 0xFF;
                    reservoirSum += mdb;
                    reservoirMax = Math.max(reservoirMax, mdb);
                    if (mdb == 0) reservoirZero++;
                    reservoirFrames++;
                }
            }
            frames++;
            last = h;
            pos += h.length;
        }
        if (pos > runStart && runStart < end) r.node(0, "MPEG audio frames", runStart, Math.min(pos, end) - runStart, "");
        if (pos < end && pos > runStart) {
            gap(s, w, pos, end, "Bytes after the last audio frame");
            gaps++;
            gapBytes += end - pos;
        }
        if (firstHeader == null) return;

        int audioFrames = frames - (infoFrame ? 1 : 0);
        double seconds = firstHeader.sampleRate == 0 ? 0 : totalSamples / (double) firstHeader.sampleRate;
        s.measuredDurationSec = seconds;
        r.codec = formats + ", " + firstHeader.sampleRate + " Hz, " + MODES[firstHeader.mode];
        if (payload != null) {
            r.audioPayloadSha256 = Bin.hex(payload.digest());
            r.audioPayloadNote = "(SHA-256 of the " + audioFrames + " audio frames, excluding tags and the encoder info frame — "
                    + "stays the same when only tags change, and equals the hash of a BareTrack clean export)";
        }
        String src = "MPEG stream";
        s.encoder(src, "Format", formats, first);
        s.encoder(src, "Audio frames", audioFrames + (infoFrame ? " (+1 Xing/Info/VBRI index frame)" : ""), first);
        s.encoder(src, "Duration", String.format(Locale.ROOT, "%.3f s (%d samples)", seconds, totalSamples), -1);
        s.encoder(src, "Sample rate", firstHeader.sampleRate + " Hz", -1);
        String brMode = bitrates.size() == 1 ? "CBR " + bitrates.keySet().iterator().next() + " kbps"
                : "VBR " + firstKey(bitrates) + "–" + lastKey(bitrates) + " kbps, mean " + Math.round(audioBytes * 8.0 / Math.max(seconds, 0.001) / 1000) + " kbps";
        s.encoder(src, "Bitrate", brMode, -1);
        s.encoder(src, "Bitrate distribution (kbps:frames)", histogram(bitrates), -1);
        s.encoder(src, "Channel modes", histogram(modes), -1);
        if (!modeExt.isEmpty()) s.encoder(src, "Joint-stereo mode extensions", histogram(modeExt), -1);
        s.encoder(src, "Header bits", String.format(Locale.ROOT, "CRC %d · padding %d · private %d · copyright %d · original %d · emphasis %s",
                crcFrames, padded, privateBits, copyrightBits, originalBits, histogram(emphasis)), -1);
        if (reservoirFrames > 0) {
            s.encoder(src, "Bit reservoir (main_data_begin)", String.format(Locale.ROOT, "mean %.1f, max %d, zero in %.1f%% of frames",
                    reservoirSum / (double) reservoirFrames, reservoirMax, 100.0 * reservoirZero / reservoirFrames), -1);
            r.fingerprint.put("mpeg.reservoir", reservoirZero == reservoirFrames ? "unused" : reservoirMax > 400 ? "deep" : "normal");
        }
        if (gaps > 0) s.encoder(src, "Non-frame regions", gaps + " totalling " + gapBytes + " bytes", -1);
        r.fingerprint.put("mpeg.format", formats);
        r.fingerprint.put("mpeg.sampleRate", Integer.toString(firstHeader.sampleRate));
        r.fingerprint.put("mpeg.bitrateMode", bitrates.size() == 1 ? "CBR " + bitrates.keySet().iterator().next() : "VBR");
        r.fingerprint.put("mpeg.channelMode", modes.size() == 1 ? modes.keySet().iterator().next() : histogramKeys(modes));
        r.fingerprint.put("mpeg.crc", crcFrames == 0 ? "off" : crcFrames == audioFrames ? "on" : "mixed");
        r.fingerprint.put("mpeg.originalBit", originalBits == 0 ? "0" : originalBits == audioFrames ? "1" : "mixed");
        if (privateBits > 0 && privateBits < audioFrames) {
            r.evidence(Evidence.Tier.SUPPORTING, "Hidden data", "MPEG private bit set in some frames only",
                    privateBits + " of " + audioFrames + " frames have the private bit set. Encoders normally leave it constant, "
                            + "so a varying pattern can carry a few bits of hidden data.", -1);
        }
        s.payload.add(new long[] {first, pos});
        s.payloadKind = "MPEG frames";
        if (s.lameFrames > 0 && Math.abs(s.lameFrames - audioFrames) > 1) {
            r.evidence(Evidence.Tier.SUPPORTING, "Edit history", "Encoder index frame count does not match the stream",
                    "The Xing/Info header records " + s.lameFrames + " frames, but " + audioFrames + " follow it. "
                            + "The file was likely trimmed, joined or re-muxed after encoding.", infoFrameOffset);
        }
        if (s.lameMusicLength > 0) {
            long actual = audioBytes + (infoFrame ? firstHeader.length : 0);
            if (Math.abs(actual - s.lameMusicLength) > 4) {
                r.evidence(Evidence.Tier.SUPPORTING, "Edit history", "LAME music length does not match the stream",
                        "LAME recorded " + s.lameMusicLength + " bytes of music; the stream now has " + actual + ".", infoFrameOffset);
            }
        }
    }

    /** Parse Xing/Info + LAME extension or VBRI in the first frame. Returns true if it is an index frame. */
    private static boolean encoderHeaders(Scan s, byte[] f, Header h, long off) {
        int[] candidates = {4 + h.sideInfo(), 4 + (h.crc ? 2 : 0) + h.sideInfo()};
        for (int x : candidates) {
            if (x + 8 > f.length) continue;
            boolean xing = Bin.ascii(f, x, "Xing"), info = Bin.ascii(f, x, "Info");
            if (!xing && !info) continue;
            String src = info ? "Info header (CBR index)" : "Xing header (VBR index)";
            s.report.node(1, src, off + x, f.length - x, "inside the first frame");
            long flags = Bin.u32be(f, x + 4);
            int p = x + 8;
            if ((flags & 1) != 0 && p + 4 <= f.length) { s.lameFrames = Bin.u32be(f, p); s.encoder(src, "Frames", Long.toString(s.lameFrames), off + p); p += 4; }
            if ((flags & 2) != 0 && p + 4 <= f.length) { s.encoder(src, "Bytes", Long.toString(Bin.u32be(f, p)), off + p); p += 4; }
            if ((flags & 4) != 0) { s.encoder(src, "Seek TOC", "100 entries", off + p); p += 100; }
            if ((flags & 8) != 0 && p + 4 <= f.length) { s.encoder(src, "Quality", Long.toString(Bin.u32be(f, p)), off + p); p += 4; }
            s.report.fingerprint.put("mpeg.indexHeader", (info ? "Info" : "Xing") + " flags " + flags);
            lame(s, f, p, off, h);
            return true;
        }
        int v = 4 + 32;
        if (v + 26 <= f.length && Bin.ascii(f, v, "VBRI")) {
            String src = "VBRI header (Fraunhofer)";
            s.report.node(1, src, off + v, f.length - v, "inside the first frame");
            s.encoder(src, "Version", Integer.toString(Bin.u16be(f, v + 4)), off + v);
            s.encoder(src, "Encoder delay", Integer.toString(Bin.u16be(f, v + 6)), off + v);
            s.encoder(src, "Quality", Integer.toString(Bin.u16be(f, v + 8)), off + v);
            s.encoder(src, "Bytes", Long.toString(Bin.u32be(f, v + 10)), off + v);
            s.lameFrames = Bin.u32be(f, v + 14);
            s.encoder(src, "Frames", Long.toString(s.lameFrames), off + v);
            s.report.fingerprint.put("encoder", "Fraunhofer VBRI");
            s.report.fingerprint.put("mpeg.indexHeader", "VBRI");
            s.encoderSummary = "Fraunhofer (VBRI header)";
            return true;
        }
        return false;
    }

    private static void lame(Scan s, byte[] f, int p, long off, Header h) {
        if (p + 36 > f.length) return;
        String ver = Bin.latin1(f, p, 9);
        String printable = ver.replaceAll("[^\\x20-\\x7E]", "");
        if (printable.trim().isEmpty()) return;
        boolean isLame = ver.startsWith("LAME") || ver.startsWith("L3.99") || ver.startsWith("Lavc") || ver.startsWith("Lavf") || ver.startsWith("GOGO");
        String src = "LAME/encoder extension";
        s.report.node(2, "Encoder tag '" + printable.trim() + "'", off + p, 36, "");
        s.encoder(src, "Encoder string", "\"" + printable + "\"", off + p);
        s.report.fingerprint.put("encoder", printable.trim());
        s.encoderSummary = printable.trim();
        if (!isLame) {
            s.report.evidence(Evidence.Tier.SUPPORTING, "Encoder", "Unusual encoder string in the index frame: \"" + printable.trim() + "\"",
                    "Not one of the common LAME/FFmpeg values; identifies the encoding pipeline.", off + p);
        }
        int revMethod = f[p + 9] & 0xFF;
        int method = revMethod & 0x0F;
        String[] methods = {"unknown", "CBR", "ABR", "VBR (rh)", "VBR (mtrh)", "VBR (mt)", "6", "7", "CBR 2-pass", "ABR 2-pass", "10", "11", "12", "13", "14", "15"};
        s.encoder(src, "Tag revision / VBR method", (revMethod >> 4) + " / " + methods[method], off + p + 9);
        s.report.fingerprint.put("encoder.vbrMethod", methods[method]);
        int lowpass = (f[p + 10] & 0xFF) * 100;
        s.lameLowpassHz = lowpass;
        s.encoder(src, "Lowpass filter", lowpass == 0 ? "not recorded" : lowpass + " Hz", off + p + 10);
        if (lowpass > 0) s.report.fingerprint.put("encoder.lowpassHz", Integer.toString(lowpass));
        float peak = Float.intBitsToFloat((int) Bin.u32be(f, p + 11));
        s.encoder(src, "ReplayGain peak", peak == 0 ? "not recorded" : String.format(Locale.ROOT, "%.6f", peak), off + p + 11);
        int radio = Bin.u16be(f, p + 15);
        if (radio != 0) s.encoder(src, "ReplayGain track", String.format(Locale.ROOT, "%s%.1f dB", (radio & 0x200) != 0 ? "-" : "+", (radio & 0x1FF) / 10.0), off + p + 15);
        int flagsAth = f[p + 19] & 0xFF;
        s.encoder(src, "Encoding flags / ATH type", String.format(Locale.ROOT, "nspsytune %d · nssafejoint %d · nogap-next %d · nogap-prev %d · ATH %d",
                (flagsAth >> 4) & 1, (flagsAth >> 5) & 1, (flagsAth >> 6) & 1, (flagsAth >> 7) & 1, flagsAth & 0x0F), off + p + 19);
        s.encoder(src, method == 2 || method == 9 ? "ABR target bitrate" : method == 1 || method == 8 ? "CBR bitrate" : "Minimum bitrate",
                (f[p + 20] & 0xFF) + " kbps" + ((f[p + 20] & 0xFF) == 255 ? "+" : ""), off + p + 20);
        int delay = ((f[p + 21] & 0xFF) << 4) | ((f[p + 22] & 0xFF) >> 4);
        int padding = ((f[p + 22] & 0x0F) << 8) | (f[p + 23] & 0xFF);
        s.encoder(src, "Encoder delay / padding (samples)", delay + " / " + padding, off + p + 21);
        s.report.fingerprint.put("encoder.delayPadding", delay + "/" + padding);
        int misc = f[p + 24] & 0xFF;
        String[] stereo = {"mono", "stereo", "dual", "joint", "forced", "auto", "intensity", "undefined"};
        String[] srcRates = {"≤32 kHz", "44.1 kHz", "48 kHz", ">48 kHz"};
        s.encoder(src, "Misc", String.format(Locale.ROOT, "noise shaping %d · stereo mode %s · unwise settings %d · source rate %s",
                misc & 3, stereo[(misc >> 2) & 7], (misc >> 5) & 1, srcRates[(misc >> 6) & 3]), off + p + 24);
        int preset = Bin.u16be(f, p + 26) & 0x07FF;
        s.encoder(src, "Preset", presetName(preset), off + p + 26);
        s.lameMusicLength = Bin.u32be(f, p + 28);
        s.encoder(src, "Music length (bytes)", Long.toString(s.lameMusicLength), off + p + 28);
        s.encoder(src, "Music CRC", String.format(Locale.ROOT, "0x%04X", Bin.u16be(f, p + 32)), off + p + 32);
        int tagCrc = Bin.u16be(f, p + 34);
        int computed = crc16(f, 0, p + 34);
        boolean match = tagCrc == computed;
        s.encoder(src, "Info tag CRC", String.format(Locale.ROOT, "stored 0x%04X, computed 0x%04X — %s", tagCrc, computed, match ? "intact" : "MISMATCH"), off + p + 34);
        if (isLame && !match && ver.startsWith("LAME")) {
            s.report.evidence(Evidence.Tier.SUPPORTING, "Edit history", "LAME info-tag CRC does not match",
                    "The first frame's encoder header was modified after LAME wrote it.", off + p + 34);
        }
    }

    static int crc16(byte[] b, int o, int n) {
        int crc = 0;
        for (int i = o; i < o + n && i < b.length; i++) {
            crc ^= b[i] & 0xFF;
            for (int k = 0; k < 8; k++) crc = (crc & 1) != 0 ? (crc >>> 1) ^ 0xA001 : crc >>> 1;
        }
        return crc & 0xFFFF;
    }

    private static String presetName(int p) {
        switch (p) {
            case 0: return "none/unknown";
            case 410: return "V9"; case 420: return "V8"; case 430: return "V7"; case 440: return "V6"; case 450: return "V5";
            case 460: return "V4"; case 470: return "V3"; case 480: return "V2 (standard)"; case 490: return "V1"; case 500: return "V0 (extreme)";
            case 1000: return "R3mix"; case 1001: return "standard"; case 1002: return "extreme"; case 1003: return "insane";
            case 1004: return "standard/fast"; case 1005: return "extreme/fast"; case 1006: return "medium"; case 1007: return "medium/fast";
            default: return p <= 320 ? "ABR/CBR " + p + " kbps" : Integer.toString(p);
        }
    }

    private static void gap(Scan s, Window w, long from, long to, String label) throws IOException {
        long n = to - from;
        if (n <= 0) return;
        byte[] data = Bin.read(s.file, from, (int) Math.min(n, 4 * 1024 * 1024));
        boolean zero = Bin.isAllZero(data, 0, data.length);
        s.report.node(0, label, from, n, Bin.preview(data, 0, data.length, 64));
        if (zero) {
            s.report.evidence(Evidence.Tier.INFO, "Container", label + " (zero-filled)", n + " bytes of zeros.", from);
            return;
        }
        int at = C2paInspector.findStore(data);
        if (at >= 0) {
            s.report.node(1, "C2PA manifest store (unreferenced bytes)", from + at, data.length - at, "");
            s.c2paStore(java.util.Arrays.copyOfRange(data, at, data.length), from + at, label);
        }
        int printable = 0;
        for (byte b : data) { int c = b & 0xFF; if (c >= 0x20 && c < 0x7F) printable++; }
        if (printable > data.length * 0.6) s.text.inspect(label, "text", new String(data, java.nio.charset.StandardCharsets.UTF_8), from);
        s.report.evidence(n >= 16 ? Evidence.Tier.SUPPORTING : Evidence.Tier.INFO, "Hidden data", label + ": " + n + " bytes",
                "Not part of any valid audio frame or recognised tag; players skip it. Content: " + Bin.preview(data, 0, data.length, 96), from);
        s.report.blob(label + " @" + Bin.hexOffset(from), "application/octet-stream", "unreferenced_" + Long.toHexString(from) + ".bin", data);
    }

    private static <K> void inc(Map<K, Integer> m, K k) { m.put(k, (m.containsKey(k) ? m.get(k) : 0) + 1); }

    private static <K> String histogram(Map<K, Integer> m) {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<K, Integer> e : m.entrySet()) {
            if (sb.length() > 0) sb.append(", ");
            sb.append(e.getKey()).append(':').append(e.getValue());
        }
        return sb.toString();
    }

    private static <K> String histogramKeys(Map<K, Integer> m) {
        StringBuilder sb = new StringBuilder();
        for (K k : m.keySet()) { if (sb.length() > 0) sb.append('+'); sb.append(k); }
        return sb.toString();
    }

    private static int firstKey(Map<Integer, Integer> m) { return m.keySet().iterator().next(); }
    private static int lastKey(Map<Integer, Integer> m) { int k = 0; for (int x : m.keySet()) k = x; return k; }
    private static String roman(int layer) { return layer == 1 ? "I" : layer == 2 ? "II" : "III"; }
}
