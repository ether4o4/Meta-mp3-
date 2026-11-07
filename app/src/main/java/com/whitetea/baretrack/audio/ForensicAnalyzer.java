package com.whitetea.baretrack.audio;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * Read-only first-pass provenance scan. It never modifies the source file.
 *
 * String matches are leads for inspection, not proof of origin. Cryptographic
 * C2PA validation and format-specific parsers are intentionally separate steps.
 */
public final class ForensicAnalyzer {
    private static final int BUFFER_SIZE = 64 * 1024;
    private static final int OVERLAP = 256;

    private static final Marker[] MARKERS = {
            new Marker("C2PA", "c2pa", "C2PA-related marker; validate a manifest and signature before attribution."),
            new Marker("SUNO", "suno", "Suno-related text marker; not proof by itself."),
            new Marker("SUNO_FINGERPRINT", "com.suno.fingerprint", "Suno-specific fingerprint string; verify its structure and binding."),
            new Marker("UDIO", "udio", "Udio-related text marker; not proof by itself."),
            new Marker("GENERATOR", "generator", "Generic generator field name."),
            new Marker("CREATION_TOOL", "creation_tool", "Generic creation-tool field name."),
            new Marker("ENCODER", "encoder", "Encoder/software marker."),
            new Marker("LAME", "lame", "LAME encoder marker."),
            new Marker("LAVF", "lavf", "FFmpeg/libavformat-related marker."),
            new Marker("XMP", "xmp", "XMP metadata marker."),
            new Marker("XML", "<?xml", "Embedded XML declaration.")
    };

    public static final class Finding {
        public final String code;
        public final String description;
        public final long firstOffset;
        public final int occurrences;

        Finding(String code, String description, long firstOffset, int occurrences) {
            this.code = code;
            this.description = description;
            this.firstOffset = firstOffset;
            this.occurrences = occurrences;
        }
    }

    public static final class Report {
        public final String fileName;
        public final long fileSize;
        public final String sha256;
        public final String detectedContainer;
        public final List<Finding> findings;

        Report(String fileName, long fileSize, String sha256, String detectedContainer, List<Finding> findings) {
            this.fileName = fileName;
            this.fileSize = fileSize;
            this.sha256 = sha256;
            this.detectedContainer = detectedContainer;
            this.findings = Collections.unmodifiableList(new ArrayList<>(findings));
        }

        public String toText() {
            StringBuilder out = new StringBuilder();
            out.append("READ-ONLY AUDIO FORENSIC REPORT\\n");
            out.append("File: ").append(fileName).append('\\n');
            out.append("Size: ").append(fileSize).append(" bytes\\n");
            out.append("SHA-256: ").append(sha256).append('\\n');
            out.append("Container: ").append(detectedContainer).append('\\n');
            out.append("String/signature leads: ").append(findings.size()).append('\\n');
            for (Finding finding : findings) {
                out.append("- ").append(finding.code)
                        .append(" | offset ").append(finding.firstOffset)
                        .append(" | occurrences ").append(finding.occurrences)
                        .append(" | ").append(finding.description).append('\\n');
            }
            out.append("Caution: marker matches are leads, not verified attribution. No audio was changed.");
            return out.toString();
        }
    }

    private static final class Marker {
        final String code;
        final byte[] needle;
        final String description;

        Marker(String code, String text, String description) {
            this.code = code;
            this.needle = text.toLowerCase(Locale.ROOT).getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            this.description = description;
        }
    }

    private static final class Match {
        long first = -1;
        int count;
    }

    private ForensicAnalyzer() {}

    public static Report analyze(File file) throws IOException {
        if (file == null || !file.isFile()) throw new IOException("Select a readable audio file first.");
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException impossible) {
            throw new IOException("SHA-256 is unavailable on this device.", impossible);
        }

        Match[] matches = new Match[MARKERS.length];
        for (int i = 0; i < matches.length; i++) matches[i] = new Match();

        byte[] buffer = new byte[BUFFER_SIZE + OVERLAP];
        int carry = 0;
        long absoluteRead = 0;
        String container;
        try (FileInputStream in = new FileInputStream(file)) {
            byte[] header = new byte[16];
            int headerCount = in.read(header);
            container = identifyContainer(header, Math.max(0, headerCount));
            digest.update(header, 0, Math.max(0, headerCount));
            scan(header, Math.max(0, headerCount), 0, matches);
            absoluteRead = Math.max(0, headerCount);

            int read;
            while ((read = in.read(buffer, carry, BUFFER_SIZE)) != -1) {
                digest.update(buffer, carry, read);
                int available = carry + read;
                long windowOffset = absoluteRead - carry;
                scan(buffer, available, windowOffset, matches);
                absoluteRead += read;
                carry = Math.min(OVERLAP, available);
                System.arraycopy(buffer, available - carry, buffer, 0, carry);
            }
        }

        List<Finding> findings = new ArrayList<>();
        for (int i = 0; i < matches.length; i++) {
            if (matches[i].count > 0) {
                findings.add(new Finding(MARKERS[i].code, MARKERS[i].description,
                        matches[i].first, matches[i].count));
            }
        }
        return new Report(file.getName(), file.length(), hex(digest.digest()), container, findings);
    }

    private static void scan(byte[] data, int length, long baseOffset, Match[] matches) {
        for (int m = 0; m < MARKERS.length; m++) {
            byte[] needle = MARKERS[m].needle;
            for (int i = 0; i <= length - needle.length; i++) {
                boolean equal = true;
                for (int j = 0; j < needle.length; j++) {
                    int value = data[i + j] & 0xFF;
                    if (value >= 'A' && value <= 'Z') value += ('a' - 'A');
                    if (value != (needle[j] & 0xFF)) { equal = false; break; }
                }
                if (equal) {
                    long offset = baseOffset + i;
                    if (matches[m].first < 0 || offset < matches[m].first) matches[m].first = offset;
                    matches[m].count++;
                }
            }
        }
    }

    private static String identifyContainer(byte[] h, int n) {
        if (n >= 3 && ascii(h, 0, "ID3")) return "MP3 with ID3 header";
        if (n >= 12 && ascii(h, 0, "RIFF") && ascii(h, 8, "WAVE")) return "RIFF/WAVE";
        if (n >= 4 && ascii(h, 0, "fLaC")) return "FLAC";
        if (n >= 4 && ascii(h, 0, "OggS")) return "Ogg";
        if (n >= 4 && ascii(h, 0, "FORM")) return "AIFF/FORM";
        if (n >= 8 && ascii(h, 4, "ftyp")) return "ISO Base Media (MP4/M4A family)";
        if (n >= 2 && (h[0] & 0xFF) == 0xFF && ((h[1] & 0xE0) == 0xE0)) return "MPEG audio candidate";
        return "Unknown or headerless audio/container";
    }

    private static boolean ascii(byte[] bytes, int offset, String expected) {
        if (offset + expected.length() > bytes.length) return false;
        for (int i = 0; i < expected.length(); i++) {
            if ((bytes[offset + i] & 0xFF) != expected.charAt(i)) return false;
        }
        return true;
    }

    private static String hex(byte[] bytes) {
        StringBuilder out = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) out.append(String.format(Locale.ROOT, "%02x", value & 0xFF));
        return out.toString();
    }
}
