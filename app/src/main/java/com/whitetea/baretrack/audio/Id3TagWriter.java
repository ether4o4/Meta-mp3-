package com.whitetea.baretrack.audio;

import com.whitetea.baretrack.model.SongTags;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/** Writes a fresh ID3v2.4 tag. The source is expected to contain only MPEG audio frames. */
public final class Id3TagWriter {
    private static final int MAX_TAG_BYTES = 1024 * 1024;

    private Id3TagWriter() {}

    public static void write(File audioOnly, File output, SongTags tags) throws IOException {
        if (audioOnly.equals(output)) throw new IOException("The source and destination must be different files.");
        if (output.exists() && !output.delete()) throw new IOException("Could not prepare the tagged output file.");
        byte[] tag = buildTag(tags);
        try (BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(output));
             BufferedInputStream in = new BufferedInputStream(new FileInputStream(audioOnly))) {
            out.write(tag);
            byte[] buffer = new byte[64 * 1024];
            int count;
            while ((count = in.read(buffer)) != -1) out.write(buffer, 0, count);
        } catch (IOException e) {
            output.delete();
            throw e;
        }
    }

    public static byte[] buildTag(SongTags tags) throws IOException {
        java.io.ByteArrayOutputStream frames = new java.io.ByteArrayOutputStream();
        textFrame(frames, "TIT2", tags.get("Title"));
        textFrame(frames, "TPE1", tags.get("Artist"));
        textFrame(frames, "TALB", tags.get("Album"));
        textFrame(frames, "TPE2", tags.get("Album artist"));
        textFrame(frames, "TCON", tags.get("Genre"));
        textFrame(frames, "TDRC", tags.get("Year"));
        textFrame(frames, "TRCK", tags.get("Track number"));
        textFrame(frames, "TPOS", tags.get("Disc number"));
        textFrame(frames, "TCOM", tags.get("Composer"));
        textFrame(frames, "TPUB", tags.get("Publisher"));
        textFrame(frames, "TCOP", tags.get("Copyright"));
        textFrame(frames, "TENC", tags.get("Encoded by"));
        textFrame(frames, "TBPM", tags.get("BPM"));
        textFrame(frames, "TIT1", tags.get("Grouping"));
        specialFrame(frames, "COMM", "eng", "", tags.get("Comment"));
        specialFrame(frames, "USLT", "eng", "", tags.get("Lyrics"));
        for (Map.Entry<String, String> entry : tags.custom().entrySet()) {
            String key = clean(entry.getKey(), 256);
            String value = clean(entry.getValue(), 8192);
            if (key.isEmpty() || value.isEmpty()) continue;
            byte[] description = key.getBytes(StandardCharsets.UTF_8);
            byte[] text = value.getBytes(StandardCharsets.UTF_8);
            java.io.ByteArrayOutputStream body = new java.io.ByteArrayOutputStream();
            body.write(3);
            body.write(description);
            body.write(0);
            body.write(text);
            frame(frames, "TXXX", body.toByteArray());
        }
        byte[] payload = frames.toByteArray();
        if (payload.length > MAX_TAG_BYTES) throw new IOException("The entered tags are too large.");
        if (payload.length == 0) return new byte[0];
        java.io.ByteArrayOutputStream result = new java.io.ByteArrayOutputStream(payload.length + 10);
        DataOutputStream out = new DataOutputStream(result);
        out.writeBytes("ID3");
        out.writeByte(4);
        out.writeByte(0);
        out.writeByte(0);
        out.write(syncSafe(payload.length));
        out.write(payload);
        out.flush();
        return result.toByteArray();
    }

    private static void textFrame(java.io.ByteArrayOutputStream out, String id, String value) throws IOException {
        String clean = clean(value, 8192);
        if (clean.isEmpty()) return;
        byte[] text = clean.getBytes(StandardCharsets.UTF_8);
        byte[] body = new byte[text.length + 1];
        body[0] = 3;
        System.arraycopy(text, 0, body, 1, text.length);
        frame(out, id, body);
    }

    private static void specialFrame(java.io.ByteArrayOutputStream out, String id, String language,
                                     String description, String value) throws IOException {
        String clean = clean(value, 8192);
        if (clean.isEmpty()) return;
        java.io.ByteArrayOutputStream body = new java.io.ByteArrayOutputStream();
        body.write(3);
        body.write(language.getBytes(StandardCharsets.US_ASCII));
        body.write(clean(description, 512).getBytes(StandardCharsets.UTF_8));
        body.write(0);
        body.write(clean.getBytes(StandardCharsets.UTF_8));
        frame(out, id, body.toByteArray());
    }

    private static void frame(java.io.ByteArrayOutputStream out, String id, byte[] body) throws IOException {
        if (body.length > 65536) throw new IOException("A tag value is too large.");
        out.write(id.getBytes(StandardCharsets.US_ASCII));
        out.write(syncSafe(body.length));
        out.write(0);
        out.write(0);
        out.write(body);
    }

    private static byte[] syncSafe(int value) {
        return new byte[] {
                (byte) ((value >> 21) & 0x7F),
                (byte) ((value >> 14) & 0x7F),
                (byte) ((value >> 7) & 0x7F),
                (byte) (value & 0x7F)
        };
    }

    private static String clean(String value, int limit) {
        if (value == null) return "";
        String normalized = value.replace('\u0000', ' ').trim();
        return normalized.length() > limit ? normalized.substring(0, limit) : normalized;
    }
}
