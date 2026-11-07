package com.whitetea.baretrack.forensics;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** Minimal RFC 8949 CBOR decoder/encoder — enough for C2PA claims, assertions and COSE_Sign1. */
final class Cbor {
    static final class Tagged {
        final long tag;
        final Object value;
        Tagged(long tag, Object value) { this.tag = tag; this.value = value; }
    }

    static final Object UNDEFINED = new Object() { @Override public String toString() { return "undefined"; } };
    private static final Object BREAK = new Object();

    private final byte[] d;
    private int p;
    private final int end;
    private int depth;

    private Cbor(byte[] d, int start, int end) {
        this.d = d;
        this.p = start;
        this.end = end;
    }

    static Object decode(byte[] data) throws IOException { return decode(data, 0, data.length); }

    static Object decode(byte[] data, int start, int end) throws IOException {
        Cbor c = new Cbor(data, start, end);
        return c.item();
    }

    private int u8() throws IOException {
        if (p >= end) throw new IOException("Truncated CBOR");
        return d[p++] & 0xFF;
    }

    private long arg(int info) throws IOException {
        if (info < 24) return info;
        if (info == 24) return u8();
        if (info == 25) return ((long) u8() << 8) | u8();
        if (info == 26) { long v = 0; for (int i = 0; i < 4; i++) v = (v << 8) | u8(); return v; }
        if (info == 27) { long v = 0; for (int i = 0; i < 8; i++) v = (v << 8) | u8(); return v; }
        if (info == 31) return -1;
        throw new IOException("Bad CBOR length encoding");
    }

    private byte[] take(long n) throws IOException {
        if (n < 0 || n > end - p) throw new IOException("CBOR item exceeds data");
        byte[] out = new byte[(int) n];
        System.arraycopy(d, p, out, 0, (int) n);
        p += (int) n;
        return out;
    }

    private Object item() throws IOException {
        if (++depth > 64) throw new IOException("CBOR nesting too deep");
        try {
            int ib = u8();
            int major = ib >> 5, info = ib & 0x1F;
            switch (major) {
                case 0: {
                    long v = arg(info);
                    if (info == 27 && v < 0) return BigInteger.valueOf(v & Long.MAX_VALUE).setBit(63);
                    return v;
                }
                case 1: return -1 - arg(info);
                case 2: case 3: {
                    long n = arg(info);
                    byte[] bytes;
                    if (n >= 0) bytes = take(n);
                    else {
                        ByteArrayOutputStream out = new ByteArrayOutputStream();
                        while (true) {
                            Object chunk = item();
                            if (chunk == BREAK) break;
                            if (chunk instanceof byte[]) out.write((byte[]) chunk, 0, ((byte[]) chunk).length);
                            else if (chunk instanceof String) { byte[] b = ((String) chunk).getBytes(StandardCharsets.UTF_8); out.write(b, 0, b.length); }
                        }
                        bytes = out.toByteArray();
                    }
                    return major == 2 ? bytes : new String(bytes, StandardCharsets.UTF_8);
                }
                case 4: {
                    long n = arg(info);
                    List<Object> list = new ArrayList<>();
                    if (n > 100000) throw new IOException("CBOR array too large");
                    if (n >= 0) for (long i = 0; i < n; i++) list.add(item());
                    else while (true) { Object o = item(); if (o == BREAK) break; list.add(o); }
                    return list;
                }
                case 5: {
                    long n = arg(info);
                    Map<Object, Object> map = new LinkedHashMap<>();
                    if (n > 100000) throw new IOException("CBOR map too large");
                    if (n >= 0) for (long i = 0; i < n; i++) { Object k = item(); map.put(k, item()); }
                    else while (true) { Object k = item(); if (k == BREAK) break; map.put(k, item()); }
                    return map;
                }
                case 6: return new Tagged(arg(info), item());
                default: {
                    if (info == 20) return Boolean.FALSE;
                    if (info == 21) return Boolean.TRUE;
                    if (info == 22) return null;
                    if (info == 23) return UNDEFINED;
                    if (info == 25) return halfFloat((int) arg(25));
                    if (info == 26) return (double) Float.intBitsToFloat((int) arg(26));
                    if (info == 27) return Double.longBitsToDouble(arg(27));
                    if (info == 31) return BREAK;
                    return "simple(" + (info < 24 ? info : arg(info)) + ")";
                }
            }
        } finally {
            depth--;
        }
    }

    private static double halfFloat(int h) {
        int exp = (h >> 10) & 0x1F, mant = h & 0x3FF;
        double v = exp == 0 ? mant * Math.pow(2, -24) : exp != 31 ? (mant + 1024) * Math.pow(2, exp - 25) : (mant == 0 ? Double.POSITIVE_INFINITY : Double.NaN);
        return (h & 0x8000) != 0 ? -v : v;
    }

    // ---- helpers for navigating decoded values ----

    static Object get(Object map, Object key) {
        if (!(map instanceof Map)) return null;
        Map<?, ?> m = (Map<?, ?>) map;
        if (m.containsKey(key)) return m.get(key);
        if (key instanceof Integer) return m.get(((Integer) key).longValue());
        return null;
    }

    static String text(Object map, String key) {
        Object v = get(map, key);
        return v instanceof String ? (String) v : null;
    }

    static Object untag(Object o) {
        while (o instanceof Tagged) o = ((Tagged) o).value;
        return o;
    }

    /** Compact human-readable rendering of a decoded value. */
    static String display(Object o, int max) {
        StringBuilder sb = new StringBuilder();
        render(o, sb, max, 0);
        return sb.length() > max ? sb.substring(0, max) + " …" : sb.toString();
    }

    private static void render(Object o, StringBuilder sb, int max, int depth) {
        if (sb.length() > max) return;
        if (o == null) sb.append("null");
        else if (o instanceof String) sb.append('"').append(o).append('"');
        else if (o instanceof byte[]) {
            byte[] b = (byte[]) o;
            sb.append("h'").append(Bin.hex(b, 0, Math.min(32, b.length))).append(b.length > 32 ? "…" : "").append("'(").append(b.length).append(')');
        } else if (o instanceof List) {
            sb.append('[');
            int i = 0;
            for (Object e : (List<?>) o) {
                if (i++ > 0) sb.append(", ");
                if (sb.length() > max) break;
                render(e, sb, max, depth + 1);
            }
            sb.append(']');
        } else if (o instanceof Map) {
            sb.append('{');
            int i = 0;
            for (Map.Entry<?, ?> e : ((Map<?, ?>) o).entrySet()) {
                if (i++ > 0) sb.append(", ");
                if (sb.length() > max) break;
                render(e.getKey(), sb, max, depth + 1);
                sb.append(": ");
                render(e.getValue(), sb, max, depth + 1);
            }
            sb.append('}');
        } else if (o instanceof Tagged) {
            sb.append(((Tagged) o).tag).append('(');
            render(((Tagged) o).value, sb, max, depth + 1);
            sb.append(')');
        } else if (o instanceof Double) sb.append(String.format(Locale.ROOT, "%s", o));
        else sb.append(o);
    }

    // ---- encoder (only what COSE Sig_structure needs) ----

    static byte[] encodeSigStructure(String context, byte[] bodyProtected, byte[] externalAad, byte[] payload) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        head(out, 4, 4);
        byte[] ctx = context.getBytes(StandardCharsets.UTF_8);
        head(out, 3, ctx.length);
        out.write(ctx, 0, ctx.length);
        for (byte[] b : new byte[][] {bodyProtected, externalAad, payload}) {
            head(out, 2, b.length);
            out.write(b, 0, b.length);
        }
        return out.toByteArray();
    }

    static void head(ByteArrayOutputStream out, int major, long n) {
        int m = major << 5;
        if (n < 24) out.write(m | (int) n);
        else if (n < 256) { out.write(m | 24); out.write((int) n); }
        else if (n < 65536) { out.write(m | 25); out.write((int) (n >> 8)); out.write((int) n); }
        else if (n < 4294967296L) { out.write(m | 26); for (int s = 24; s >= 0; s -= 8) out.write((int) (n >> s)); }
        else { out.write(m | 27); for (int s = 56; s >= 0; s -= 8) out.write((int) (n >> s)); }
    }
}
