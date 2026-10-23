package com.whitetea.baretrack.audio;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.ArrayList;

/** Keeps only a validated WAV format chunk and its audio samples. */
public final class WavSanitizer {
    private static final long UINT32_MAX = 0xFFFFFFFFL;
    private static final int MAX_FMT_BYTES = 4096;

    private static final class Segment {
        final long offset;
        final long length;
        Segment(long offset, long length) { this.offset = offset; this.length = length; }
    }

    private static final class Layout {
        byte[] format;
        int blockAlign;
        long audioBytes;
        final ArrayList<Segment> data = new ArrayList<>();
    }

    private WavSanitizer() {}

    public static boolean isWave(File file) throws IOException {
        if (!file.isFile() || file.length() < 12) return false;
        try (RandomAccessFile in = new RandomAccessFile(file, "r")) {
            byte[] header = new byte[12];
            in.readFully(header);
            return ascii(header, 0, "RIFF") && ascii(header, 8, "WAVE");
        }
    }

    public static void strip(File input, File output) throws IOException {
        rewrite(input, output, null);
    }

    static void rewriteWithId3(File input, File output, byte[] id3Tag) throws IOException {
        rewrite(input, output, id3Tag);
    }

    private static void rewrite(File input, File output, byte[] id3Tag) throws IOException {
        if (input.equals(output)) throw new IOException("The source and destination must be different files.");
        if (output.exists() && !output.delete()) throw new IOException("Could not prepare the clean output file.");
        try {
            Layout layout;
            try (RandomAccessFile source = new RandomAccessFile(input, "r")) {
                layout = inspect(source);
                writeCleanWave(source, output, layout, id3Tag);
            }
        } catch (IOException e) {
            output.delete();
            throw e;
        }
    }

    private static Layout inspect(RandomAccessFile source) throws IOException {
        long length = source.length();
        if (length < 12) throw new IOException("This file is not a complete RIFF/WAVE file.");
        byte[] header = new byte[12];
        source.seek(0);
        source.readFully(header);
        if (!ascii(header, 0, "RIFF") || !ascii(header, 8, "WAVE")) {
            throw new IOException("This is not a standard little-endian WAV file.");
        }
        long riffSize = uint32(header, 4);
        long riffEnd = 8 + riffSize;
        if (riffSize < 4 || riffEnd > length) throw new IOException("The WAV container has an invalid RIFF size.");

        Layout layout = new Layout();
        long position = 12;
        while (position < riffEnd) {
            if (riffEnd - position < 8) throw new IOException("The WAV container has a truncated chunk header.");
            source.seek(position);
            byte[] chunkHeader = new byte[8];
            source.readFully(chunkHeader);
            long chunkSize = uint32(chunkHeader, 4);
            long payload = position + 8;
            long chunkEnd = payload + chunkSize;
            long paddedEnd = chunkEnd + (chunkSize & 1L);
            if (chunkEnd < payload || paddedEnd > riffEnd) throw new IOException("The WAV container has a truncated chunk.");

            if (ascii(chunkHeader, 0, "fmt ")) {
                if (layout.format != null) throw new IOException("The WAV file has more than one format chunk.");
                if (chunkSize < 16 || chunkSize > MAX_FMT_BYTES) throw new IOException("The WAV format chunk is unsupported.");
                byte[] format = new byte[(int) chunkSize];
                source.seek(payload);
                source.readFully(format);
                layout.format = normalizedFormat(format, layout);
            } else if (ascii(chunkHeader, 0, "data")) {
                layout.data.add(new Segment(payload, chunkSize));
                if (Long.MAX_VALUE - layout.audioBytes < chunkSize) throw new IOException("The WAV audio data is too large.");
                layout.audioBytes += chunkSize;
            }
            position = paddedEnd;
        }
        if (position != riffEnd) throw new IOException("The WAV container has an invalid chunk boundary.");
        if (layout.format == null) throw new IOException("The WAV file has no supported format chunk.");
        if (layout.data.isEmpty() || layout.audioBytes == 0) throw new IOException("The WAV file has no audio data.");
        if (layout.audioBytes % layout.blockAlign != 0) throw new IOException("The WAV audio data does not match its sample format.");
        return layout;
    }

    private static byte[] normalizedFormat(byte[] original, Layout layout) throws IOException {
        int tag = uint16(original, 0);
        int channels = uint16(original, 2);
        long sampleRate = uint32(original, 4);
        int blockAlign = uint16(original, 12);
        int bitsPerSample = uint16(original, 14);
        int formatLength = 16;

        if (tag == 0xFFFE) {
            if (original.length < 40 || uint16(original, 16) < 22) {
                throw new IOException("The WAV extensible format chunk is incomplete.");
            }
            int validBits = uint16(original, 18);
            if (validBits == 0 || validBits > bitsPerSample) throw new IOException("The WAV valid-bit count is invalid.");
            byte[] subformat = new byte[16];
            System.arraycopy(original, 24, subformat, 0, subformat.length);
            int subTag = subformatTag(subformat);
            if (subTag != 1 && subTag != 3) throw new IOException("Only PCM or IEEE-float WAV audio is supported.");
            tag = subTag;
            formatLength = 40;
        }
        if (tag != 1 && tag != 3) throw new IOException("Only PCM or IEEE-float WAV audio is supported.");
        if (channels < 1 || channels > 64 || sampleRate == 0 || bitsPerSample < 8 || bitsPerSample > 64) {
            throw new IOException("The WAV sample format is invalid.");
        }
        if (tag == 3 && bitsPerSample != 32 && bitsPerSample != 64) {
            throw new IOException("IEEE-float WAV audio must use 32-bit or 64-bit samples.");
        }
        int bytesPerSample = (bitsPerSample + 7) / 8;
        long expectedAlign = (long) channels * bytesPerSample;
        if (expectedAlign > 0xFFFF || blockAlign != expectedAlign) throw new IOException("The WAV block alignment is invalid.");
        layout.blockAlign = blockAlign;
        byte[] normalized = new byte[formatLength];
        System.arraycopy(original, 0, normalized, 0, formatLength);
        return normalized;
    }

    private static int subformatTag(byte[] guid) {
        byte[] tail = {0, 0, 0x10, 0, (byte) 0x80, 0, 0, (byte) 0xAA, 0, 0x38, (byte) 0x9B, 0x71};
        for (int i = 0; i < tail.length; i++) if (guid[i + 4] != tail[i]) return -1;
        if (guid[1] != 0 || guid[2] != 0 || guid[3] != 0) return -1;
        return guid[0] & 0xFF;
    }

    private static void writeCleanWave(RandomAccessFile source, File output, Layout layout, byte[] id3Tag) throws IOException {
        byte[] tag = id3Tag == null ? new byte[0] : id3Tag;
        if (tag.length > 0 && tag.length > UINT32_MAX) throw new IOException("The entered tags are too large.");
        long totalSize = 12L + 8 + layout.format.length + (layout.format.length & 1)
                + (tag.length == 0 ? 0 : 8L + tag.length + (tag.length & 1))
                + 8 + layout.audioBytes + (layout.audioBytes & 1);
        if (totalSize - 8 > UINT32_MAX || layout.audioBytes > UINT32_MAX) {
            throw new IOException("WAV files larger than 4 GB are not supported.");
        }
        byte[] buffer = new byte[64 * 1024];
        try (RandomAccessFile out = new RandomAccessFile(output, "rw")) {
            out.setLength(0);
            out.writeBytes("RIFF"); writeUInt32(out, 0); out.writeBytes("WAVE");
            writeChunkHeader(out, "fmt ", layout.format.length);
            out.write(layout.format);
            if ((layout.format.length & 1) != 0) out.write(0);
            if (tag.length > 0) {
                writeChunkHeader(out, "id3 ", tag.length);
                out.write(tag);
                if ((tag.length & 1) != 0) out.write(0);
            }
            writeChunkHeader(out, "data", layout.audioBytes);
            for (Segment segment : layout.data) {
                source.seek(segment.offset);
                long remaining = segment.length;
                while (remaining > 0) {
                    int count = (int) Math.min(buffer.length, remaining);
                    source.readFully(buffer, 0, count);
                    out.write(buffer, 0, count);
                    remaining -= count;
                }
            }
            if ((layout.audioBytes & 1L) != 0) out.write(0);
            long riffSize = out.length() - 8;
            out.seek(4);
            writeUInt32(out, riffSize);
            out.getFD().sync();
        }
    }

    private static void writeChunkHeader(RandomAccessFile out, String id, long size) throws IOException {
        out.writeBytes(id);
        writeUInt32(out, size);
    }

    private static void writeUInt32(RandomAccessFile out, long value) throws IOException {
        if (value < 0 || value > UINT32_MAX) throw new IOException("A WAV chunk exceeds the RIFF size limit.");
        out.write((int) (value & 0xFF));
        out.write((int) ((value >> 8) & 0xFF));
        out.write((int) ((value >> 16) & 0xFF));
        out.write((int) ((value >> 24) & 0xFF));
    }

    private static int uint16(byte[] bytes, int offset) {
        return (bytes[offset] & 0xFF) | ((bytes[offset + 1] & 0xFF) << 8);
    }

    private static long uint32(byte[] bytes, int offset) {
        return ((long) bytes[offset] & 0xFF)
                | (((long) bytes[offset + 1] & 0xFF) << 8)
                | (((long) bytes[offset + 2] & 0xFF) << 16)
                | (((long) bytes[offset + 3] & 0xFF) << 24);
    }

    private static boolean ascii(byte[] bytes, int offset, String expected) {
        for (int i = 0; i < expected.length(); i++) if ((bytes[offset + i] & 0xFF) != expected.charAt(i)) return false;
        return true;
    }
}
