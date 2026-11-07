package com.whitetea.baretrack.forensics;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

/** Small byte helpers shared by the read-only parsers. */
final class Bin {
    private Bin() {}

    static int u8(byte[] b, int o) { return b[o] & 0xFF; }
    static int u16be(byte[] b, int o) { return ((b[o] & 0xFF) << 8) | (b[o + 1] & 0xFF); }
    static int u16le(byte[] b, int o) { return (b[o] & 0xFF) | ((b[o + 1] & 0xFF) << 8); }
    static int u24be(byte[] b, int o) { return ((b[o] & 0xFF) << 16) | ((b[o + 1] & 0xFF) << 8) | (b[o + 2] & 0xFF); }
    static long u32be(byte[] b, int o) {
        return ((long) (b[o] & 0xFF) << 24) | ((b[o + 1] & 0xFF) << 16) | ((b[o + 2] & 0xFF) << 8) | (b[o + 3] & 0xFF);
    }
    static long u32le(byte[] b, int o) {
        return (b[o] & 0xFF) | ((b[o + 1] & 0xFF) << 8) | ((b[o + 2] & 0xFF) << 16) | ((long) (b[o + 3] & 0xFF) << 24);
    }
    static long u64be(byte[] b, int o) { return (u32be(b, o) << 32) | u32be(b, o + 4); }
    static long u64le(byte[] b, int o) { return u32le(b, o) | (u32le(b, o + 4) << 32); }
    static int s16le(byte[] b, int o) { return (short) u16le(b, o); }
    static int synchsafe(byte[] b, int o) {
        return ((b[o] & 0x7F) << 21) | ((b[o + 1] & 0x7F) << 14) | ((b[o + 2] & 0x7F) << 7) | (b[o + 3] & 0x7F);
    }

    static boolean ascii(byte[] b, int o, String s) {
        if (o < 0 || o + s.length() > b.length) return false;
        for (int i = 0; i < s.length(); i++) if ((b[o + i] & 0xFF) != s.charAt(i)) return false;
        return true;
    }

    static String fourcc(byte[] b, int o) {
        StringBuilder out = new StringBuilder(4);
        for (int i = 0; i < 4 && o + i < b.length; i++) {
            int c = b[o + i] & 0xFF;
            out.append(c >= 0x20 && c < 0x7F ? (char) c : (c == 0xA9 ? '©' : '?'));
        }
        return out.toString();
    }

    static String latin1(byte[] b, int o, int n) {
        if (o >= b.length || n <= 0) return "";
        n = Math.min(n, b.length - o);
        return new String(b, o, n, StandardCharsets.ISO_8859_1);
    }

    /** Fixed-width text field, trimmed at the first NUL and of trailing whitespace. */
    static String fixed(byte[] b, int o, int n) {
        if (o >= b.length) return "";
        n = Math.min(n, b.length - o);
        int end = o;
        while (end < o + n && b[end] != 0) end++;
        return new String(b, o, end - o, StandardCharsets.ISO_8859_1).trim();
    }

    static String utf8(byte[] b, int o, int n) {
        if (o >= b.length || n <= 0) return "";
        n = Math.min(n, b.length - o);
        return new String(b, o, n, StandardCharsets.UTF_8);
    }

    static byte[] read(RandomAccessFile f, long offset, int n) throws IOException {
        if (n < 0) throw new IOException("Negative read length.");
        long available = f.length() - offset;
        if (offset < 0 || available <= 0) return new byte[0];
        int count = (int) Math.min(n, available);
        byte[] out = new byte[count];
        f.seek(offset);
        f.readFully(out);
        return out;
    }

    static String hex(byte[] b) { return hex(b, 0, b.length); }

    static String hex(byte[] b, int o, int n) {
        StringBuilder out = new StringBuilder(n * 2);
        for (int i = o; i < o + n && i < b.length; i++) out.append(String.format(Locale.ROOT, "%02x", b[i] & 0xFF));
        return out.toString();
    }

    static String hexOffset(long offset) { return offset < 0 ? "-" : String.format(Locale.ROOT, "0x%X", offset); }

    /** Readable preview of arbitrary bytes: text when mostly printable, otherwise hex. */
    static String preview(byte[] b, int o, int n, int max) {
        if (b == null || o >= b.length || n <= 0) return "(empty)";
        n = Math.min(n, b.length - o);
        int shown = Math.min(n, max);
        int printable = 0;
        for (int i = o; i < o + shown; i++) {
            int c = b[i] & 0xFF;
            if ((c >= 0x20 && c < 0x7F) || c == '\n' || c == '\r' || c == '\t') printable++;
        }
        boolean allZero = true;
        for (int i = o; i < o + n; i++) if (b[i] != 0) { allZero = false; break; }
        if (allZero) return "(" + n + " zero bytes)";
        String suffix = n > shown ? " … (" + n + " bytes)" : "";
        if (printable >= shown * 0.85) {
            StringBuilder s = new StringBuilder();
            for (int i = o; i < o + shown; i++) {
                int c = b[i] & 0xFF;
                s.append(c >= 0x20 && c < 0x7F ? (char) c : (c == '\n' || c == '\r' || c == '\t' ? ' ' : '.'));
            }
            return "\"" + s.toString().trim() + "\"" + suffix;
        }
        return "hex " + hex(b, o, Math.min(shown, 48)) + (n > 48 ? " …" : "") + (n > shown || n > 48 ? " (" + n + " bytes)" : "");
    }

    static boolean isAllZero(byte[] b, int o, int n) {
        for (int i = o; i < o + n && i < b.length; i++) if (b[i] != 0) return false;
        return true;
    }

    static String bytes(long n) {
        if (n < 1024) return n + " B";
        if (n < 1024 * 1024) return String.format(Locale.ROOT, "%.1f KiB", n / 1024.0);
        return String.format(Locale.ROOT, "%.2f MiB", n / (1024.0 * 1024.0));
    }

    static String clean(String s) {
        if (s == null) return "";
        StringBuilder out = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == 0) out.append('␀');
            else if (c < 0x20 && c != '\n' && c != '\t') out.append(' ');
            else out.append(c);
        }
        return out.toString().trim();
    }

    static String clip(String s, int max) {
        if (s == null) return "";
        return s.length() <= max ? s : s.substring(0, max) + " … (" + s.length() + " chars)";
    }

    /** Base64 / base64url decoder (java.util.Base64 needs API 26; minSdk is 23). */
    static byte[] base64(String text) {
        int[] map = new int[128];
        java.util.Arrays.fill(map, -1);
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for (int i = 0; i < alphabet.length(); i++) map[alphabet.charAt(i)] = i;
        map['-'] = 62;
        map['_'] = 63;
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream(text.length() * 3 / 4);
        int buffer = 0, bits = 0;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == '=' ) break;
            if (c == '\n' || c == '\r' || c == ' ' || c == '\t') continue;
            if (c >= 128 || map[c] < 0) throw new IllegalArgumentException("Not base64");
            buffer = (buffer << 6) | map[c];
            bits += 6;
            if (bits >= 8) {
                bits -= 8;
                out.write((buffer >> bits) & 0xFF);
            }
        }
        return out.toByteArray();
    }

    /** String.join needs API 26. */
    static String join(String sep, Iterable<String> parts) {
        StringBuilder sb = new StringBuilder();
        for (String p : parts) {
            if (sb.length() > 0) sb.append(sep);
            sb.append(p);
        }
        return sb.toString();
    }

    static String base64Encode(byte[] data) {
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        StringBuilder sb = new StringBuilder((data.length + 2) / 3 * 4);
        for (int i = 0; i < data.length; i += 3) {
            int b = (data[i] & 0xFF) << 16 | (i + 1 < data.length ? (data[i + 1] & 0xFF) << 8 : 0) | (i + 2 < data.length ? data[i + 2] & 0xFF : 0);
            sb.append(alphabet.charAt((b >> 18) & 63)).append(alphabet.charAt((b >> 12) & 63));
            sb.append(i + 1 < data.length ? alphabet.charAt((b >> 6) & 63) : '=');
            sb.append(i + 2 < data.length ? alphabet.charAt(b & 63) : '=');
        }
        return sb.toString();
    }
}
