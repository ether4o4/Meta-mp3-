package com.whitetea.baretrack.audio;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.whitetea.baretrack.model.SongTags;

import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

public final class WavSanitizerTest {
    @Test public void removesNonAudioChunksAndPreservesSamples() throws Exception {
        File dir = Files.createTempDirectory("baretrack-wav-strip").toFile();
        File source = new File(dir, "input.wav");
        File clean = new File(dir, "clean.wav");
        byte[] samples = {0, 1, 2, 3, 4, 5, 6, 7};
        byte[] privateInfo = "INFOINAMhidden title".getBytes(StandardCharsets.US_ASCII);
        byte[] bext = {9, 8, 7};
        byte[] input = riff(chunk("fmt ", pcmFormat()), chunk("LIST", privateInfo),
                chunk("bext", bext), chunk("id3 ", "hidden tag".getBytes(StandardCharsets.US_ASCII)),
                chunk("JUNK", new byte[] {1, 2, 3}), chunk("data", samples));
        write(source, input);

        assertTrue(WavSanitizer.isWave(source));
        WavSanitizer.strip(source, clean);
        assertArrayEquals(riff(chunk("fmt ", pcmFormat()), chunk("data", samples)), Files.readAllBytes(clean.toPath()));
        String output = new String(Files.readAllBytes(clean.toPath()), StandardCharsets.ISO_8859_1);
        assertFalse(output.contains("hidden title"));
        assertFalse(output.contains("bext"));
        assertFalse(output.contains("id3 "));
    }

    @Test public void writesFreshId3ChunkAndCanStripItAgain() throws Exception {
        File dir = Files.createTempDirectory("baretrack-wav-retag").toFile();
        File raw = new File(dir, "raw.wav");
        File tagged = new File(dir, "tagged.wav");
        File stripped = new File(dir, "stripped.wav");
        byte[] samples = {11, 12, 13, 14, 15, 16, 17, 18};
        byte[] cleanWave = riff(chunk("fmt ", pcmFormat()), chunk("data", samples));
        write(raw, cleanWave);

        SongTags tags = new SongTags();
        tags.set("Title", "User chosen title");
        tags.set("Artist", "User chosen artist");
        WavTagWriter.write(raw, tagged, tags);
        byte[] withTags = Files.readAllBytes(tagged.toPath());
        assertTrue(contains(withTags, "id3 "));
        assertTrue(contains(withTags, "User chosen title"));

        WavSanitizer.strip(tagged, stripped);
        assertArrayEquals(cleanWave, Files.readAllBytes(stripped.toPath()));
    }

    @Test public void rejectsCompressedWavInsteadOfDroppingItsCodec() throws Exception {
        File dir = Files.createTempDirectory("baretrack-wav-codec").toFile();
        File source = new File(dir, "compressed.wav");
        File clean = new File(dir, "clean.wav");
        byte[] compressedFormat = pcmFormat();
        compressedFormat[0] = 2; // Microsoft ADPCM
        compressedFormat[1] = 0;
        write(source, riff(chunk("fmt ", compressedFormat), chunk("data", new byte[] {1, 2, 3, 4})));
        try {
            WavSanitizer.strip(source, clean);
            fail("Compressed WAV must be rejected because its codec is not preserved.");
        } catch (java.io.IOException expected) {
            assertFalse(clean.exists());
        }
    }

    @Test public void combinesMultipleDataChunksInOrder() throws Exception {
        File dir = Files.createTempDirectory("baretrack-wav-multi-data").toFile();
        File source = new File(dir, "input.wav");
        File clean = new File(dir, "clean.wav");
        byte[] first = {1, 2, 3, 4};
        byte[] second = {5, 6, 7, 8};
        write(source, riff(chunk("fmt ", pcmFormat()), chunk("data", first),
                chunk("LIST", new byte[] {9}), chunk("data", second)));
        WavSanitizer.strip(source, clean);
        assertArrayEquals(riff(chunk("fmt ", pcmFormat()), chunk("data", join(first, second))),
                Files.readAllBytes(clean.toPath()));
    }

    private static byte[] pcmFormat() throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        put16(out, 1);       // PCM
        put16(out, 1);       // mono
        put32(out, 8000);    // sample rate
        put32(out, 16000);   // byte rate
        put16(out, 2);       // block align
        put16(out, 16);      // bits per sample
        return out.toByteArray();
    }

    private static byte[] chunk(String id, byte[] payload) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(id.getBytes(StandardCharsets.US_ASCII));
        put32(out, payload.length);
        out.write(payload);
        if ((payload.length & 1) != 0) out.write(0);
        return out.toByteArray();
    }

    private static byte[] riff(byte[]... chunks) throws Exception {
        byte[] body = join(chunks);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write("RIFF".getBytes(StandardCharsets.US_ASCII));
        put32(out, 4 + body.length);
        out.write("WAVE".getBytes(StandardCharsets.US_ASCII));
        out.write(body);
        return out.toByteArray();
    }

    private static byte[] join(byte[]... chunks) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] chunk : chunks) out.write(chunk);
        return out.toByteArray();
    }

    private static void put16(ByteArrayOutputStream out, int value) {
        out.write(value & 0xFF);
        out.write((value >> 8) & 0xFF);
    }

    private static void put32(ByteArrayOutputStream out, long value) {
        out.write((int) (value & 0xFF));
        out.write((int) ((value >> 8) & 0xFF));
        out.write((int) ((value >> 16) & 0xFF));
        out.write((int) ((value >> 24) & 0xFF));
    }

    private static boolean contains(byte[] value, String needle) {
        byte[] bytes = needle.getBytes(StandardCharsets.ISO_8859_1);
        outer: for (int i = 0; i <= value.length - bytes.length; i++) {
            for (int j = 0; j < bytes.length; j++) if (value[i + j] != bytes[j]) continue outer;
            return true;
        }
        return false;
    }

    private static void write(File file, byte[] bytes) throws Exception {
        try (FileOutputStream out = new FileOutputStream(file)) { out.write(bytes); }
    }
}
