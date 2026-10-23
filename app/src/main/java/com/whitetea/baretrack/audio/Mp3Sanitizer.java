package com.whitetea.baretrack.audio;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;

/** Keeps valid MPEG Layer III frames and drops everything outside the audio stream. */
public final class Mp3Sanitizer {
    private static final int[] MPEG1_BITRATES = {0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0};
    private static final int[] MPEG2_BITRATES = {0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0};
    private static final int[] BASE_SAMPLE_RATES = {44100, 48000, 32000};
    private static final int MAX_FRAME_SIZE = 4096;

    public static final class Result {
        public final long inputBytes;
        public final long audioBytes;
        public final int frames;
        public final boolean encoderIndexRemoved;

        Result(long inputBytes, long audioBytes, int frames, boolean encoderIndexRemoved) {
            this.inputBytes = inputBytes;
            this.audioBytes = audioBytes;
            this.frames = frames;
            this.encoderIndexRemoved = encoderIndexRemoved;
        }

        public long removedBytes() { return inputBytes - audioBytes; }
    }

    private static final class Frame {
        final int length;
        final boolean hasIndex;
        Frame(int length, boolean hasIndex) { this.length = length; this.hasIndex = hasIndex; }
    }

    private Mp3Sanitizer() {}

    public static Result strip(File input, File output) throws IOException {
        if (input.equals(output)) throw new IOException("The source and destination must be different files.");
        if (output.exists() && !output.delete()) throw new IOException("Could not prepare the clean output file.");
        long length = input.length();
        long written = 0;
        int frames = 0;
        boolean encoderIndexRemoved = false;
        byte[] frameBuffer = new byte[MAX_FRAME_SIZE];

        try (RandomAccessFile source = new RandomAccessFile(input, "r");
             BufferedOutputStream sink = new BufferedOutputStream(new FileOutputStream(output), 64 * 1024)) {
            long first = findFirstFrame(source, length);
            if (first < 0) throw new IOException("This file does not contain a readable MP3 audio stream.");
            long position = first;
            while (position + 4 <= length) {
                Frame frame = parseFrame(source, position, length);
                if (frame == null) {
                    long next = findNextFrame(source, position + 1, length);
                    if (next < 0) break;
                    position = next;
                    continue;
                }
                if (frames == 0 && frame.hasIndex) {
                    encoderIndexRemoved = true;
                } else {
                    source.seek(position);
                    int remaining = frame.length;
                    while (remaining > 0) {
                        int count = Math.min(remaining, frameBuffer.length);
                        source.readFully(frameBuffer, 0, count);
                        sink.write(frameBuffer, 0, count);
                        remaining -= count;
                    }
                    written += frame.length;
                }
                frames++;
                position += frame.length;
            }
        } catch (IOException e) {
            if (output.exists()) output.delete();
            throw e;
        }
        if (frames < 2 || written == 0) {
            output.delete();
            throw new IOException("The file is too short or damaged to contain a usable MP3 stream.");
        }
        return new Result(length, written, frames, encoderIndexRemoved);
    }

    private static long findFirstFrame(RandomAccessFile file, long length) throws IOException {
        return findNextFrame(file, 0, length);
    }

    private static long findNextFrame(RandomAccessFile file, long start, long length) throws IOException {
        byte[] scan = new byte[64 * 1024 + 3];
        final int step = 64 * 1024;
        for (long base = start; base + 4 <= length; base += step) {
            int count = (int) Math.min(scan.length, length - base);
            if (count < 4) break;
            file.seek(base);
            file.readFully(scan, 0, count);
            int limit = count - 3;
            for (int i = 0; i < limit; i++) {
                if ((scan[i] & 0xFF) != 0xFF || (scan[i + 1] & 0xE0) != 0xE0) continue;
                long offset = base + i;
                Frame current = parseFrame(file, offset, length);
                if (current == null) continue;
                long nextOffset = offset + current.length;
                if (parseFrame(file, nextOffset, length) != null || nextOffset == length) return offset;
            }
        }
        return -1;
    }

    private static Frame parseFrame(RandomAccessFile file, long offset, long fileLength) throws IOException {
        if (offset < 0 || offset + 4 > fileLength) return null;
        file.seek(offset);
        int b0 = file.readUnsignedByte();
        int b1 = file.readUnsignedByte();
        int b2 = file.readUnsignedByte();
        int b3 = file.readUnsignedByte();
        if (b0 != 0xFF || (b1 & 0xE0) != 0xE0) return null;

        int version = (b1 >> 3) & 0x03;
        int layer = (b1 >> 1) & 0x03;
        int bitrateIndex = (b2 >> 4) & 0x0F;
        int sampleIndex = (b2 >> 2) & 0x03;
        int padding = (b2 >> 1) & 0x01;
        if (version == 1 || layer != 1 || bitrateIndex == 0 || bitrateIndex == 15 || sampleIndex == 3) return null;

        int[] bitrates = version == 3 ? MPEG1_BITRATES : MPEG2_BITRATES;
        int sampleRate = BASE_SAMPLE_RATES[sampleIndex];
        if (version == 2) sampleRate /= 2;
        else if (version == 0) sampleRate /= 4;
        int coefficient = version == 3 ? 144 : 72;
        int frameLength = (coefficient * bitrates[bitrateIndex] * 1000) / sampleRate + padding;
        if (frameLength < 24 || frameLength > MAX_FRAME_SIZE || offset + frameLength > fileLength) return null;

        boolean mono = ((b3 >> 6) & 0x03) == 3;
        boolean crcPresent = (b1 & 0x01) == 0;
        int sideInfo = version == 3 ? (mono ? 17 : 32) : (mono ? 9 : 17);
        int mainDataStart = 4 + (crcPresent ? 2 : 0) + sideInfo;
        boolean index = false;
        if (mainDataStart + 4 <= frameLength) {
            byte[] marker = new byte[4];
            file.seek(offset + mainDataStart);
            file.readFully(marker);
            index = ascii(marker, "Xing") || ascii(marker, "Info");
        }
        if (!index && 4 + 32 + 4 <= frameLength) {
            byte[] marker = new byte[4];
            file.seek(offset + 4 + 32);
            file.readFully(marker);
            index = ascii(marker, "VBRI");
        }
        return new Frame(frameLength, index);
    }

    private static boolean ascii(byte[] value, String marker) {
        for (int i = 0; i < marker.length(); i++) if ((value[i] & 0xFF) != marker.charAt(i)) return false;
        return true;
    }
}
