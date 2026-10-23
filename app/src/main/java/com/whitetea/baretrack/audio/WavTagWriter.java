package com.whitetea.baretrack.audio;

import com.whitetea.baretrack.model.SongTags;

import java.io.File;
import java.io.IOException;

/** Writes a fresh ID3v2.4 chunk into a sanitized WAV container. */
public final class WavTagWriter {
    private WavTagWriter() {}

    public static void write(File audioOnlyWave, File output, SongTags tags) throws IOException {
        byte[] id3 = Id3TagWriter.buildTag(tags);
        WavSanitizer.rewriteWithId3(audioOnlyWave, output, id3);
    }
}
