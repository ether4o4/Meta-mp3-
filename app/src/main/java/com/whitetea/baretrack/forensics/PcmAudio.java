package com.whitetea.baretrack.forensics;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;

/** Decoded samples handed to the signal analyser, plus a pure-Java reader for PCM WAV/AIFF. */
public final class PcmAudio {
    /** Supplies decoded audio for compressed formats (Android MediaCodec in the app). */
    public interface Provider {
        PcmAudio decode(File file, int maxSeconds) throws IOException;
    }

    public final float[][] channels;
    public final int sampleRate;
    public final int frames;
    public final String decoder;
    /** For integer PCM: the smallest bit depth that represents every sample exactly (0 if unknown). */
    public final int effectiveBits;
    public final int containerBits;
    public final boolean truncated;
    /** Quantised 16-bit view, used for exact-duplicate block detection. */
    final short[] mono16;

    public PcmAudio(float[][] channels, int sampleRate, int frames, String decoder, int effectiveBits, int containerBits, boolean truncated) {
        this.channels = channels;
        this.sampleRate = sampleRate;
        this.frames = frames;
        this.decoder = decoder;
        this.effectiveBits = effectiveBits;
        this.containerBits = containerBits;
        this.truncated = truncated;
        this.mono16 = new short[frames];
        for (int i = 0; i < frames; i++) {
            float sum = 0;
            for (float[] c : channels) sum += c[i];
            float v = sum / channels.length;
            this.mono16[i] = (short) Math.max(-32768, Math.min(32767, Math.round(v * 32767f)));
        }
    }

    /** Reads integer/float PCM from RIFF WAVE or AIFF/AIFF-C (NONE, sowt, twos, fl32). Returns null for other codecs. */
    static PcmAudio readPcm(File file, int maxSeconds) throws IOException {
        try (RandomAccessFile f = new RandomAccessFile(file, "r")) {
            byte[] h = Bin.read(f, 0, 12);
            if (h.length < 12) return null;
            boolean riff = Bin.ascii(h, 0, "RIFF") && Bin.ascii(h, 8, "WAVE");
            boolean aiff = Bin.ascii(h, 0, "FORM") && (Bin.ascii(h, 8, "AIFF") || Bin.ascii(h, 8, "AIFC"));
            if (!riff && !aiff) return null;
            int channels = 0, bits = 0, rate = 0, format = 0;
            boolean bigEndian = aiff, isFloat = false;
            long dataOff = -1, dataLen = 0;
            long p = 12, end = f.length();
            while (p + 8 <= end) {
                byte[] ch = Bin.read(f, p, 8);
                String id = Bin.fourcc(ch, 0);
                long size = aiff ? Bin.u32be(ch, 4) : Bin.u32le(ch, 4);
                long body = p + 8;
                if (riff && id.equals("fmt ")) {
                    byte[] d = Bin.read(f, body, (int) Math.min(size, 64));
                    format = Bin.u16le(d, 0);
                    channels = Bin.u16le(d, 2);
                    rate = (int) Bin.u32le(d, 4);
                    bits = Bin.u16le(d, 14);
                    if (format == 0xFFFE && d.length >= 26) format = Bin.u16le(d, 24);
                    if (format != 1 && format != 3) return null;
                    isFloat = format == 3;
                } else if (riff && id.equals("data")) {
                    dataOff = body;
                    dataLen = Math.min(size, end - body);
                } else if (aiff && id.equals("COMM")) {
                    byte[] d = Bin.read(f, body, (int) Math.min(size, 64));
                    channels = Bin.u16be(d, 0);
                    bits = Bin.u16be(d, 6);
                    rate = (int) Math.round(IffParser.extended(d, 8));
                    if (size >= 22) {
                        String comp = Bin.fourcc(d, 18);
                        if (comp.equals("sowt")) bigEndian = false;
                        else if (comp.equals("fl32") || comp.equals("FL32")) isFloat = true;
                        else if (!comp.equals("NONE") && !comp.equals("twos")) return null;
                    }
                } else if (aiff && id.equals("SSND")) {
                    byte[] d = Bin.read(f, body, 8);
                    long o = Bin.u32be(d, 0);
                    dataOff = body + 8 + o;
                    dataLen = Math.min(size - 8 - o, end - dataOff);
                }
                p = body + size + (size % 2);
            }
            if (dataOff < 0 || channels <= 0 || rate <= 0 || bits <= 0 || bits > 64) return null;
            int bytesPer = (bits + 7) / 8;
            int frameBytes = bytesPer * channels;
            long totalFrames = dataLen / frameBytes;
            long maxFrames = (long) rate * maxSeconds;
            boolean truncated = totalFrames > maxFrames;
            int n = (int) Math.min(totalFrames, maxFrames);
            int keep = Math.min(channels, 2);
            float[][] out = new float[keep][n];
            long orBits = 0;
            byte[] buf = new byte[frameBytes * 4096];
            f.seek(dataOff);
            int done = 0;
            while (done < n) {
                int chunk = Math.min(4096, n - done);
                f.readFully(buf, 0, chunk * frameBytes);
                for (int i = 0; i < chunk; i++) {
                    for (int c = 0; c < keep; c++) {
                        int o = i * frameBytes + c * bytesPer;
                        float v;
                        if (isFloat) {
                            if (bytesPer == 4) {
                                int raw = bigEndian ? (int) Bin.u32be(buf, o) : (int) Bin.u32le(buf, o);
                                v = Float.intBitsToFloat(raw);
                            } else {
                                long raw = bigEndian ? Bin.u64be(buf, o) : Bin.u64le(buf, o);
                                v = (float) Double.longBitsToDouble(raw);
                            }
                        } else {
                            long sample = 0;
                            for (int k = 0; k < bytesPer; k++) {
                                int byteVal = buf[o + (bigEndian ? k : bytesPer - 1 - k)] & 0xFF;
                                sample = (sample << 8) | byteVal;
                            }
                            int shift = 64 - bytesPer * 8;
                            if (bytesPer == 1 && !aiff) sample -= 128; // 8-bit WAV is unsigned
                            else sample = (sample << shift) >> shift;
                            orBits |= sample;
                            v = (float) (sample / Math.pow(2, bytesPer * 8 - 1));
                        }
                        out[c][done + i] = v;
                    }
                }
                done += chunk;
            }
            int effective = 0;
            if (!isFloat && orBits != 0) {
                int zeros = Long.numberOfTrailingZeros(orBits);
                effective = bytesPer * 8 - zeros;
            }
            String dec = (riff ? "WAV" : "AIFF") + " " + (isFloat ? "float" : "PCM") + " reader (exact samples)"
                    + (channels > 2 ? ", first 2 of " + channels + " channels" : "");
            return new PcmAudio(out, rate, n, dec, effective, bits, truncated);
        }
    }
}
