package com.whitetea.baretrack.model;

import java.util.LinkedHashMap;
import java.util.Map;

public final class SongTags {
    public static final String[] FIELDS = {
            "Title", "Artist", "Album", "Album artist", "Genre", "Year", "Track number",
            "Disc number", "Composer", "Comment", "Lyrics", "Publisher", "Copyright",
            "Encoded by", "BPM", "Grouping"
    };

    private final LinkedHashMap<String, String> values = new LinkedHashMap<>();
    private final LinkedHashMap<String, String> custom = new LinkedHashMap<>();

    public String get(String key) { return values.getOrDefault(key, ""); }
    public void set(String key, String value) {
        if (key == null || value == null) return;
        values.put(key, value.trim());
    }
    public Map<String, String> values() { return new LinkedHashMap<>(values); }
    public Map<String, String> custom() { return new LinkedHashMap<>(custom); }
    public void setCustom(String key, String value) {
        if (key == null || value == null) return;
        String cleanKey = key.trim();
        String cleanValue = value.trim();
        if (!cleanKey.isEmpty() && !cleanValue.isEmpty()) custom.put(cleanKey, cleanValue);
    }
    public boolean isEmpty() {
        for (String value : values.values()) if (value != null && !value.isEmpty()) return false;
        return custom.isEmpty();
    }
    public static SongTags blank() { return new SongTags(); }
}
