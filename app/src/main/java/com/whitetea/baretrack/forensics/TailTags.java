package com.whitetea.baretrack.forensics;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/** Trailing tag blocks: ID3v1/1.1, enhanced TAG+, Lyrics3 v1/v2, APEv1/v2 and appended ID3v2.4 (footer). */
final class TailTags {
    private TailTags() {}

    /** Parses trailing tags and returns the offset where the audio/container data ends. */
    static long parse(Scan s, long end) throws IOException {
        boolean progressed = true;
        int guard = 0;
        while (progressed && end > 0 && guard++ < 8) {
            progressed = false;
            if (end >= 128) {
                byte[] t = Bin.read(s.file, end - 128, 128);
                if (Bin.ascii(t, 0, "TAG")) {
                    id3v1(s, t, end - 128);
                    end -= 128;
                    progressed = true;
                    if (end >= 227) {
                        byte[] plus = Bin.read(s.file, end - 227, 4);
                        if (Bin.ascii(plus, 0, "TAG+")) {
                            byte[] e = Bin.read(s.file, end - 227, 227);
                            s.report.node(0, "Enhanced TAG+ block", end - 227, 227, "");
                            s.meta("TAG+", "Title (extended)", Bin.fixed(e, 4, 60), end - 227);
                            s.meta("TAG+", "Artist (extended)", Bin.fixed(e, 64, 60), end - 227);
                            s.meta("TAG+", "Album (extended)", Bin.fixed(e, 124, 60), end - 227);
                            s.meta("TAG+", "Genre (free text)", Bin.fixed(e, 185, 30), end - 227);
                            end -= 227;
                        }
                    }
                    continue;
                }
            }
            if (end >= 15) {
                byte[] t = Bin.read(s.file, end - 15, 15);
                if (Bin.ascii(t, 6, "LYRICS200")) {
                    int size;
                    try { size = Integer.parseInt(Bin.latin1(t, 0, 6)); } catch (NumberFormatException e) { size = -1; }
                    if (size > 0 && end - 15 - size >= 0) {
                        long start = end - 15 - size;
                        byte[] body = Bin.read(s.file, start, size);
                        s.report.node(0, "Lyrics3 v2 tag", start, size + 15, "");
                        if (Bin.ascii(body, 0, "LYRICSBEGIN")) lyrics3Fields(s, body, start);
                        s.report.evidence(Evidence.Tier.INFO, "Container", "Lyrics3 v2 block present",
                                "Legacy Winamp-era lyric tag; most modern players ignore it.", start);
                        end = start;
                        progressed = true;
                        continue;
                    }
                }
                if (Bin.ascii(t, 6, "LYRICSEND")) {
                    long scanFrom = Math.max(0, end - 5100);
                    byte[] region = Bin.read(s.file, scanFrom, (int) (end - scanFrom));
                    String text = new String(region, StandardCharsets.ISO_8859_1);
                    int b = text.lastIndexOf("LYRICSBEGIN");
                    if (b >= 0) {
                        long start = scanFrom + b;
                        s.report.node(0, "Lyrics3 v1 tag", start, end - start, "");
                        s.meta("Lyrics3 v1", "Lyrics", text.substring(b + 11, text.length() - 9), start);
                        end = start;
                        progressed = true;
                        continue;
                    }
                }
            }
            if (end >= 32) {
                byte[] f = Bin.read(s.file, end - 32, 32);
                if (Bin.ascii(f, 0, "APETAGEX")) {
                    long version = Bin.u32le(f, 8), size = Bin.u32le(f, 12), items = Bin.u32le(f, 16), flags = Bin.u32le(f, 20);
                    boolean header = (flags & 0x80000000L) != 0;
                    long start = end - size - (header ? 32 : 0);
                    if (size >= 32 && start >= 0) {
                        s.report.node(0, "APE" + (version >= 2000 ? "v2" : "v1") + " tag", start, end - start, items + " items");
                        byte[] body = Bin.read(s.file, end - size, (int) Math.min(size - 32, 16 * 1024 * 1024));
                        apeItems(s, body, end - size, (int) items);
                        end = start;
                        progressed = true;
                        continue;
                    }
                }
            }
            if (end >= 10) {
                byte[] f = Bin.read(s.file, end - 10, 10);
                if (Bin.ascii(f, 0, "3DI") && (f[3] & 0xFF) == 4) {
                    int size = Bin.synchsafe(f, 6);
                    long start = end - 10 - size - 10;
                    if (start >= 0) {
                        long used = Id3v2Parser.parse(s, start, 0, "appended at end of file");
                        if (used > 0) {
                            s.report.evidence(Evidence.Tier.INFO, "Container", "ID3v2.4 tag appended at the end of the file",
                                    "Appended tags are written by a minority of tools and are missed by many readers.", start);
                            end = start;
                            progressed = true;
                        }
                    }
                }
            }
        }
        return end;
    }

    private static void id3v1(Scan s, byte[] t, long off) {
        boolean v11 = t[125] == 0 && t[126] != 0;
        String src = v11 ? "ID3v1.1" : "ID3v1";
        s.report.node(0, src + " tag", off, 128, "");
        s.meta(src, "Title", Bin.fixed(t, 3, 30), off);
        s.meta(src, "Artist", Bin.fixed(t, 33, 30), off);
        s.meta(src, "Album", Bin.fixed(t, 63, 30), off);
        s.meta(src, "Year", Bin.fixed(t, 93, 4), off);
        s.meta(src, "Comment", Bin.fixed(t, 97, v11 ? 28 : 30), off);
        if (v11) s.meta(src, "Track", Integer.toString(t[126] & 0xFF), off);
        s.meta(src, "Genre index", Integer.toString(t[127] & 0xFF), off);
        // Bytes after the NUL inside fixed fields are invisible to readers.
        int[][] fields = {{3, 30}, {33, 30}, {63, 30}, {97, v11 ? 28 : 30}};
        for (int[] f : fields) {
            int z = f[0];
            while (z < f[0] + f[1] && t[z] != 0) z++;
            if (z < f[0] + f[1] && !Bin.isAllZero(t, z, f[0] + f[1] - z)) {
                boolean spaces = true;
                for (int i = z + 1; i < f[0] + f[1]; i++) if (t[i] != 0 && t[i] != ' ') spaces = false;
                if (!spaces) {
                    s.report.evidence(Evidence.Tier.SUPPORTING, "Hidden data", "Bytes hidden after a terminator in an ID3v1 field",
                            Bin.preview(t, z, f[0] + f[1] - z, 40), off + z);
                }
            }
        }
        s.report.fingerprint.putIfAbsent("id3v1", src);
    }

    private static void lyrics3Fields(Scan s, byte[] body, long base) {
        int p = 11;
        while (p + 8 <= body.length) {
            String id = Bin.latin1(body, p, 3);
            int len;
            try { len = Integer.parseInt(Bin.latin1(body, p + 3, 5)); } catch (NumberFormatException e) { break; }
            if (p + 8 + len > body.length) break;
            s.meta("Lyrics3 v2", id, Bin.latin1(body, p + 8, len), base + p);
            p += 8 + len;
        }
    }

    private static void apeItems(Scan s, byte[] b, long base, int items) {
        int p = 0;
        for (int i = 0; i < items && p + 9 <= b.length; i++) {
            int len = (int) Bin.u32le(b, p);
            long flags = Bin.u32le(b, p + 4);
            int k = p + 8;
            while (k < b.length && b[k] != 0) k++;
            String key = Bin.latin1(b, p + 8, k - p - 8);
            int v = k + 1;
            if (len < 0 || v + len > b.length) break;
            int kind = (int) ((flags >> 1) & 3);
            if (kind == 1) {
                byte[] bin = java.util.Arrays.copyOfRange(b, v, v + len);
                s.meta("APE", key, "binary " + len + " bytes: " + Bin.preview(bin, 0, bin.length, 80), base + p);
                if (key.toLowerCase(java.util.Locale.ROOT).startsWith("cover art")) {
                    int z = 0;
                    while (z < bin.length && bin[z] != 0) z++;
                    byte[] img = java.util.Arrays.copyOfRange(bin, Math.min(bin.length, z + 1), bin.length);
                    s.images.inspect("APE " + key, img, -1, "");
                }
            } else {
                s.meta("APE", key, Bin.utf8(b, v, len).replace('\u0000', '/'), base + p);
            }
            p = v + len;
        }
    }
}
