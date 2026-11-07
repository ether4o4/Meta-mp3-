package com.whitetea.baretrack.forensics;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;

/** Complete, read-only examination result for one file. */
public final class ForensicReport {
    public static final String SECTION_FILE = "File & hashes";
    public static final String SECTION_METADATA = "Metadata";
    public static final String SECTION_C2PA = "C2PA content credentials";
    public static final String SECTION_ENCODER = "Encoder & export fingerprint";
    public static final String SECTION_SIGNAL = "Audio signal";
    public static final String SECTION_STRINGS = "Hidden identifiers & strings";
    public static final String SECTION_COMPARE = "Cross-platform comparison";

    /** One structural element: chunk, atom, frame run, tag, padding or gap. */
    public static final class Node {
        public final int depth;
        public final String type;
        public final long offset;
        public final long size;
        public final String note;

        Node(int depth, String type, long offset, long size, String note) {
            this.depth = depth;
            this.type = type;
            this.offset = offset;
            this.size = size;
            this.note = note == null ? "" : note;
        }

        boolean contains(long position) { return position >= offset && position < offset + Math.max(1, size); }
    }

    /** One decoded value. */
    public static final class Field {
        public final String section;
        public final String source;
        public final String key;
        public final String value;
        public final long offset;

        Field(String section, String source, String key, String value, long offset) {
            this.section = section;
            this.source = source;
            this.key = key;
            this.value = value == null ? "" : value;
            this.offset = offset;
        }
    }

    /** A payload worth exporting on its own (C2PA manifest store, cover art, embedded object). */
    public static final class Blob {
        public final String label;
        public final String mime;
        public final String suggestedName;
        public final byte[] data;

        Blob(String label, String mime, String suggestedName, byte[] data) {
            this.label = label;
            this.mime = mime;
            this.suggestedName = suggestedName;
            this.data = data;
        }
    }

    public String fileName = "";
    public long fileSize;
    public String sha256 = "";
    public String sha1 = "";
    public String md5 = "";
    public String audioPayloadSha256 = "";
    public String audioPayloadNote = "";
    public String container = "Unknown";
    public String codec = "";
    public long elapsedMs;
    public final List<Node> structure = new ArrayList<>();
    public final List<Field> fields = new ArrayList<>();
    public final List<Evidence> evidence = new ArrayList<>();
    public final List<Blob> blobs = new ArrayList<>();
    public final List<String> limitations = new ArrayList<>();
    public final Fingerprint fingerprint = new Fingerprint();
    public C2paInspector.Result c2pa;

    void node(int depth, String type, long offset, long size, String note) {
        structure.add(new Node(depth, type, offset, size, note));
    }

    void field(String section, String source, String key, String value, long offset) {
        if (value == null) return;
        fields.add(new Field(section, source, key, Bin.clip(Bin.clean(value), 4000), offset));
    }

    void evidence(Evidence.Tier tier, String category, String title, String detail, long offset) {
        for (Evidence e : evidence) {
            if (e.tier == tier && e.title.equals(title) && e.offset == offset) return;
        }
        evidence.add(new Evidence(tier, category, title, detail, offset));
    }

    void blob(String label, String mime, String name, byte[] data) {
        if (data == null || data.length == 0) return;
        for (Blob b : blobs) if (b.data.length == data.length && java.util.Arrays.equals(b.data, data)) return;
        blobs.add(new Blob(label, mime, name, data));
    }

    void limitation(String text) { if (!limitations.contains(text)) limitations.add(text); }

    /** Innermost structural element containing an offset, for attributing raw string hits. */
    public String locate(long offset) {
        Node best = null;
        for (Node n : structure) {
            if (n.size <= 0 || !n.contains(offset)) continue;
            if (best == null || n.size <= best.size) best = n;
        }
        return best == null ? "outside parsed structures" : best.type;
    }

    public List<Evidence> evidenceSorted() {
        List<Evidence> sorted = new ArrayList<>(evidence);
        Collections.sort(sorted, new Comparator<Evidence>() {
            @Override public int compare(Evidence a, Evidence b) {
                if (a.tier != b.tier) return a.tier.ordinal() - b.tier.ordinal();
                return priority(a.category) - priority(b.category);
            }
        });
        return sorted;
    }

    private static int priority(String category) {
        switch (category) {
            case "C2PA": return 0;
            case "Fingerprint": return 1;
            case "AI declaration": return 2;
            case "Generator identity": return 3;
            case "Export fingerprint": return 4;
            case "Application data": return 5;
            case "Encoder": return 6;
            case "Export pipeline": return 7;
            case "Edit history": return 8;
            case "Hidden data": return 9;
            default: return 20;
        }
    }

    /** Structure in file order, with depth recomputed from byte containment. */
    public List<Node> structureSorted() {
        List<Node> sorted = new ArrayList<>(structure);
        Collections.sort(sorted, new Comparator<Node>() {
            @Override public int compare(Node a, Node b) {
                if (a.offset != b.offset) return a.offset < b.offset ? -1 : 1;
                return a.size == b.size ? 0 : (a.size > b.size ? -1 : 1);
            }
        });
        List<Node> out = new ArrayList<>();
        List<Node> stack = new ArrayList<>();
        for (Node n : sorted) {
            while (!stack.isEmpty()) {
                Node top = stack.get(stack.size() - 1);
                if (n.offset >= top.offset && n.offset + Math.max(0, n.size) <= top.offset + top.size && n != top && top.size > 0) break;
                stack.remove(stack.size() - 1);
            }
            out.add(new Node(stack.size(), n.type, n.offset, n.size, n.note));
            if (n.size > 0) stack.add(n);
        }
        return out;
    }

    public Evidence.Tier strongestTier() {
        Evidence.Tier best = Evidence.Tier.INFO;
        for (Evidence e : evidence) if (e.tier.ordinal() < best.ordinal()) best = e.tier;
        return best;
    }

    public String verdict() {
        List<Evidence> sorted = evidenceSorted();
        Evidence top = null;
        for (Evidence e : sorted) {
            if (e.tier != Evidence.Tier.INFO && e.tier != Evidence.Tier.INCONCLUSIVE) { top = e; break; }
        }
        if (top == null) {
            return "No attribution evidence found in this copy. Absence of markers does not establish that the audio "
                    + "was not AI-generated or not from a given service: metadata is easy to strip and older downloads "
                    + "carry no credentials.";
        }
        int confirmed = count(Evidence.Tier.CONFIRMED), probable = count(Evidence.Tier.PROBABLE), supporting = count(Evidence.Tier.SUPPORTING);
        return top.tier.label.toUpperCase(Locale.ROOT) + ": " + top.title
                + String.format(Locale.ROOT, "  [%d confirmed · %d probable · %d supporting]", confirmed, probable, supporting);
    }

    public int count(Evidence.Tier tier) {
        int n = 0;
        for (Evidence e : evidence) if (e.tier == tier) n++;
        return n;
    }

    public List<Field> fields(String section) {
        List<Field> out = new ArrayList<>();
        for (Field f : fields) if (f.section.equals(section)) out.add(f);
        return out;
    }

    public String toText() {
        StringBuilder out = new StringBuilder(16 * 1024);
        out.append("AUDIO PROVENANCE EXAMINATION  (read-only — the examined file was not modified)\n");
        out.append(line()).append("VERDICT\n").append(verdict()).append("\n\n");

        out.append(line()).append("1. ").append(SECTION_FILE.toUpperCase(Locale.ROOT)).append('\n');
        kv(out, "File", fileName);
        kv(out, "Size", fileSize + " bytes (" + Bin.bytes(fileSize) + ")");
        kv(out, "Container", container);
        if (!codec.isEmpty()) kv(out, "Codec", codec);
        kv(out, "SHA-256", sha256);
        kv(out, "SHA-1", sha1);
        kv(out, "MD5", md5);
        if (!audioPayloadSha256.isEmpty()) kv(out, "Audio payload SHA-256", audioPayloadSha256 + "  " + audioPayloadNote);
        appendFields(out, SECTION_FILE);

        out.append('\n').append(line()).append("2. CONTAINER DISSECTION (").append(structure.size()).append(" elements)\n");
        for (Node n : structureSorted()) {
            for (int i = 0; i < n.depth; i++) out.append("  ");
            out.append("• ").append(n.type).append("  @").append(Bin.hexOffset(n.offset))
                    .append("  ").append(n.size).append(" B");
            if (!n.note.isEmpty()) out.append("  — ").append(n.note);
            out.append('\n');
        }

        section(out, "3. ", SECTION_METADATA);
        section(out, "4. ", SECTION_C2PA);
        section(out, "5. ", SECTION_ENCODER);
        section(out, "6. ", SECTION_SIGNAL);
        section(out, "7. ", SECTION_STRINGS);
        section(out, "8. ", SECTION_COMPARE);

        out.append('\n').append(line()).append("9. EVIDENCE REPORT\n");
        for (Evidence.Tier tier : Evidence.Tier.values()) {
            List<Evidence> group = new ArrayList<>();
            for (Evidence e : evidenceSorted()) if (e.tier == tier) group.add(e);
            out.append('\n').append(tier.label.toUpperCase(Locale.ROOT)).append(" (").append(group.size()).append(")\n");
            if (group.isEmpty()) out.append("  none\n");
            for (Evidence e : group) {
                out.append("  ▸ [").append(e.category).append("] ").append(e.title);
                if (e.offset >= 0) out.append("  @").append(Bin.hexOffset(e.offset));
                out.append('\n');
                if (!e.detail.isEmpty()) out.append("    ").append(e.detail.replace("\n", "\n    ")).append('\n');
            }
        }

        out.append('\n').append(line()).append("10. LIMITS OF THIS EXAMINATION\n");
        for (String l : limitations) out.append("  - ").append(l).append('\n');
        out.append(String.format(Locale.ROOT, "\nExamined in %d ms.\n", elapsedMs));
        return out.toString();
    }

    private void section(StringBuilder out, String number, String section) {
        List<Field> list = fields(section);
        out.append('\n').append(line()).append(number).append(section.toUpperCase(Locale.ROOT))
                .append(" (").append(list.size()).append(")\n");
        if (list.isEmpty()) out.append("  none found\n");
        appendFields(out, section);
    }

    private void appendFields(StringBuilder out, String section) {
        String lastSource = null;
        for (Field f : fields) {
            if (!f.section.equals(section)) continue;
            if (!f.source.equals(lastSource)) {
                out.append("  [").append(f.source).append("]\n");
                lastSource = f.source;
            }
            out.append("    ").append(f.key).append(": ").append(f.value.replace("\n", "\n      "));
            if (f.offset >= 0) out.append("  @").append(Bin.hexOffset(f.offset));
            out.append('\n');
        }
    }

    private static void kv(StringBuilder out, String k, String v) { out.append("  ").append(k).append(": ").append(v).append('\n'); }
    private static String line() { return "────────────────────────────────────────\n"; }

    public String toJson() {
        Json j = new Json();
        j.begin();
        j.str("fileName", fileName).num("fileSize", fileSize).str("container", container).str("codec", codec)
                .str("sha256", sha256).str("sha1", sha1).str("md5", md5)
                .str("audioPayloadSha256", audioPayloadSha256).str("verdict", verdict())
                .str("strongestTier", strongestTier().name());
        j.array("structure");
        for (Node n : structureSorted()) {
            j.begin().num("depth", n.depth).str("type", n.type).num("offset", n.offset).num("size", n.size).str("note", n.note).end();
        }
        j.endArray();
        j.array("fields");
        for (Field f : fields) {
            j.begin().str("section", f.section).str("source", f.source).str("key", f.key).str("value", f.value).num("offset", f.offset).end();
        }
        j.endArray();
        j.array("evidence");
        for (Evidence e : evidenceSorted()) {
            j.begin().str("tier", e.tier.name()).str("category", e.category).str("title", e.title).str("detail", e.detail).num("offset", e.offset).end();
        }
        j.endArray();
        j.array("fingerprint");
        for (java.util.Map.Entry<String, String> e : fingerprint.features().entrySet()) {
            j.begin().str("feature", e.getKey()).str("value", e.getValue()).end();
        }
        j.endArray();
        j.array("limitations");
        for (String l : limitations) j.value(l);
        j.endArray();
        j.end();
        return j.toString();
    }

    /** Minimal streaming JSON writer; avoids an org.json dependency so the engine runs in plain JVM tests. */
    static final class Json {
        private final StringBuilder sb = new StringBuilder();
        private boolean needComma;

        Json begin() { comma(); sb.append('{'); needComma = false; return this; }
        Json end() { sb.append('}'); needComma = true; return this; }
        Json array(String key) { key(key); sb.append('['); needComma = false; return this; }
        Json endArray() { sb.append(']'); needComma = true; return this; }
        Json str(String key, String value) { key(key); quote(value); needComma = true; return this; }
        Json num(String key, long value) { key(key); sb.append(value); needComma = true; return this; }
        Json value(String value) { comma(); quote(value); needComma = true; return this; }

        private void key(String key) { comma(); quote(key); sb.append(':'); needComma = false; }
        private void comma() { if (needComma) sb.append(','); }

        private void quote(String s) {
            sb.append('"');
            if (s != null) {
                for (int i = 0; i < s.length(); i++) {
                    char c = s.charAt(i);
                    switch (c) {
                        case '"': sb.append("\\\""); break;
                        case '\\': sb.append("\\\\"); break;
                        case '\n': sb.append("\\n"); break;
                        case '\r': sb.append("\\r"); break;
                        case '\t': sb.append("\\t"); break;
                        default:
                            if (c < 0x20) sb.append(String.format(Locale.ROOT, "\\u%04x", (int) c));
                            else sb.append(c);
                    }
                }
            }
            sb.append('"');
        }

        @Override public String toString() { return sb.toString(); }
    }
}
