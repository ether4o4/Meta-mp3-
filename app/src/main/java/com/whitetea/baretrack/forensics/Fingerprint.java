package com.whitetea.baretrack.forensics;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;

/**
 * Export/production fingerprint: the structural and encoder traits that survive retagging and renaming.
 * Saved fingerprints act as user-verified reference profiles (for example, "known Suno download") that
 * later files are compared against. No profiles are bundled, so nothing is asserted that you did not verify.
 */
public final class Fingerprint {
    private static final Map<String, Integer> WEIGHTS = new LinkedHashMap<>();
    static {
        WEIGHTS.put("c2pa.signer.sha256", 8);
        WEIGHTS.put("c2pa.generator", 5);
        WEIGHTS.put("c2pa.issuer", 3);
        WEIGHTS.put("id3.privOwners", 4);
        WEIGHTS.put("id3.geobTypes", 3);
        WEIGHTS.put("id3.frameSet", 3);
        WEIGHTS.put("encoder", 4);
        WEIGHTS.put("encoder.vbrMethod", 2);
        WEIGHTS.put("encoder.lowpassHz", 2);
        WEIGHTS.put("encoder.delayPadding", 2);
        WEIGHTS.put("riff.chunkOrder", 4);
        WEIGHTS.put("mp4.atomOrder", 4);
        WEIGHTS.put("mp4.handler", 2);
        WEIGHTS.put("vendor", 4);
        WEIGHTS.put("flac.blockOrder", 3);
        WEIGHTS.put("artwork", 2);
    }

    private final LinkedHashMap<String, String> features = new LinkedHashMap<>();

    public void put(String key, String value) {
        if (value == null || value.trim().isEmpty()) return;
        features.put(key, value.trim());
    }

    public void putIfAbsent(String key, String value) { if (!features.containsKey(key)) put(key, value); }
    public String get(String key) { return features.get(key); }
    public Map<String, String> features() { return Collections.unmodifiableMap(features); }
    public boolean isEmpty() { return features.isEmpty(); }

    static int weight(String key) {
        Integer w = WEIGHTS.get(key);
        return w == null ? 1 : w;
    }

    /** A saved, user-labelled reference profile. */
    public static final class Reference {
        public final String id;
        public final String label;
        public final String sourceFile;
        public final long savedAt;
        public final Fingerprint fingerprint;

        public Reference(String id, String label, String sourceFile, long savedAt, Fingerprint fingerprint) {
            this.id = id;
            this.label = label;
            this.sourceFile = sourceFile;
            this.savedAt = savedAt;
            this.fingerprint = fingerprint;
        }
    }

    public static final class Comparison {
        public final Reference reference;
        public final int percent;
        public final int matchedWeight;
        public final int totalWeight;
        public final List<String> matched;
        public final List<String> differed;

        Comparison(Reference reference, int matchedWeight, int totalWeight, List<String> matched, List<String> differed) {
            this.reference = reference;
            this.matchedWeight = matchedWeight;
            this.totalWeight = totalWeight;
            this.percent = totalWeight == 0 ? 0 : Math.round(100f * matchedWeight / totalWeight);
            this.matched = matched;
            this.differed = differed;
        }
    }

    /** Weighted agreement over the features the reference defines and this file also exposes. */
    public Comparison compareTo(Reference reference) {
        int matched = 0, total = 0;
        List<String> same = new ArrayList<>(), diff = new ArrayList<>();
        for (Map.Entry<String, String> e : reference.fingerprint.features.entrySet()) {
            String key = e.getKey();
            if (key.startsWith("info.")) continue;
            String mine = features.get(key);
            int w = weight(key);
            total += w;
            if (mine != null && mine.equalsIgnoreCase(e.getValue())) {
                matched += w;
                same.add(key);
            } else {
                diff.add(key + " (" + (mine == null ? "absent" : mine) + " vs " + e.getValue() + ")");
            }
        }
        return new Comparison(reference, matched, total, same, diff);
    }

    /** Stores reference profiles as plain properties files in an app-private directory. */
    public static final class Store {
        private final File dir;

        public Store(File dir) {
            this.dir = dir;
            //noinspection ResultOfMethodCallIgnored
            dir.mkdirs();
        }

        public Reference save(String label, String sourceFile, Fingerprint fp) throws IOException {
            String id = Long.toString(System.currentTimeMillis(), 36) + Integer.toString((int) (Math.random() * 1e6), 36);
            Properties p = new Properties();
            p.setProperty("meta.label", label);
            p.setProperty("meta.source", sourceFile == null ? "" : sourceFile);
            long now = System.currentTimeMillis();
            p.setProperty("meta.savedAt", Long.toString(now));
            for (Map.Entry<String, String> e : fp.features.entrySet()) p.setProperty("f." + e.getKey(), e.getValue());
            File target = new File(dir, id + ".fingerprint");
            try (OutputStream out = new FileOutputStream(target)) {
                p.store(out, "BareTrack reference fingerprint");
            }
            return new Reference(id, label, sourceFile, now, fp);
        }

        public List<Reference> list() {
            List<Reference> out = new ArrayList<>();
            File[] files = dir.listFiles((d, name) -> name.endsWith(".fingerprint"));
            if (files == null) return out;
            for (File f : files) {
                Properties p = new Properties();
                try (InputStream in = new FileInputStream(f)) {
                    p.load(in);
                } catch (IOException e) {
                    continue;
                }
                Fingerprint fp = new Fingerprint();
                for (String name : p.stringPropertyNames()) {
                    if (name.startsWith("f.")) fp.features.put(name.substring(2), p.getProperty(name));
                }
                long saved = 0;
                try { saved = Long.parseLong(p.getProperty("meta.savedAt", "0")); } catch (NumberFormatException ignored) { }
                String id = f.getName().substring(0, f.getName().length() - ".fingerprint".length());
                out.add(new Reference(id, p.getProperty("meta.label", id), p.getProperty("meta.source", ""), saved, fp));
            }
            Collections.sort(out, (a, b) -> Long.compare(b.savedAt, a.savedAt));
            return out;
        }

        public boolean delete(String id) { return new File(dir, id + ".fingerprint").delete(); }
    }

    static String bucket(double hz, int step) {
        return String.format(Locale.ROOT, "%d", (int) (Math.round(hz / step) * step));
    }
}
