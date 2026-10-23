package com.whitetea.baretrack.audio;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import com.whitetea.baretrack.model.SongTags;

import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Arrays;

public final class Mp3SanitizerTest {
    @Test public void stripsTagBlocksAndKeepsMpegFramesByteForByte() throws Exception {
        File dir = Files.createTempDirectory("baretrack-test").toFile();
        File source = new File(dir, "input.mp3");
        File cleaned = new File(dir, "clean.mp3");
        byte[] first = frame(false);
        byte[] second = frame(false);
        byte[] third = frame(false);
        ByteArrayOutputStream input = new ByteArrayOutputStream();
        input.write(id3Tag());
        input.write(first);
        input.write(second);
        input.write(third);
        input.write("APETAGEX".getBytes(StandardCharsets.US_ASCII));
        input.write(new byte[40]);
        input.write("TAG".getBytes(StandardCharsets.US_ASCII));
        input.write(new byte[125]);
        write(source, input.toByteArray());

        Mp3Sanitizer.Result result = Mp3Sanitizer.strip(source, cleaned);
        assertEquals(3, result.frames);
        assertArrayEquals(join(first, second, third), Files.readAllBytes(cleaned.toPath()));
        assertTrue(result.removedBytes() > 150);
    }

    @Test public void removesRecognizedEncoderIndexFrame() throws Exception {
        File dir = Files.createTempDirectory("baretrack-index-test").toFile();
        File source = new File(dir, "input.mp3");
        File cleaned = new File(dir, "clean.mp3");
        byte[] indexFrame = frame(true);
        byte[] second = frame(false);
        byte[] third = frame(false);
        write(source, join(indexFrame, second, third));

        Mp3Sanitizer.Result result = Mp3Sanitizer.strip(source, cleaned);
        assertTrue(result.encoderIndexRemoved);
        assertArrayEquals(join(second, third), Files.readAllBytes(cleaned.toPath()));
    }

    @Test public void freshTagsAreRemovedOnTheNextDeepStrip() throws Exception {
        File dir = Files.createTempDirectory("baretrack-retag-test").toFile();
        File raw = new File(dir, "raw.mp3");
        File tagged = new File(dir, "tagged.mp3");
        File strippedAgain = new File(dir, "stripped.mp3");
        byte[] audio = join(frame(false), frame(false), frame(false));
        write(raw, audio);

        SongTags tags = new SongTags();
        tags.set("Title", "Only the title I entered");
        tags.set("Artist", "My own artist");
        tags.setCustom("Private note", "custom value");
        Id3TagWriter.write(raw, tagged, tags);
        byte[] withTags = Files.readAllBytes(tagged.toPath());
        assertEquals('I', withTags[0]);
        assertEquals('D', withTags[1]);
        assertEquals('3', withTags[2]);

        Mp3Sanitizer.strip(tagged, strippedAgain);
        assertArrayEquals(audio, Files.readAllBytes(strippedAgain.toPath()));
    }

    private static byte[] frame(boolean xing) {
        byte[] bytes = new byte[417];
        bytes[0] = (byte) 0xFF;
        bytes[1] = (byte) 0xFB;
        bytes[2] = (byte) 0x90;
        bytes[3] = 0x64;
        if (xing) System.arraycopy("Xing".getBytes(StandardCharsets.US_ASCII), 0, bytes, 36, 4);
        return bytes;
    }

    private static byte[] id3Tag() throws Exception {
        byte[] tag = new byte[16];
        tag[0] = 'I'; tag[1] = 'D'; tag[2] = '3';
        tag[3] = 4; tag[4] = 0; tag[5] = 0;
        tag[9] = 6;
        byte[] frame = "PRIVxx".getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(frame, 0, tag, 10, frame.length);
        return tag;
    }

    private static byte[] join(byte[]... chunks) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] chunk : chunks) out.write(chunk);
        return out.toByteArray();
    }

    private static void write(File file, byte[] bytes) throws Exception {
        try (FileOutputStream out = new FileOutputStream(file)) { out.write(bytes); }
    }
}
