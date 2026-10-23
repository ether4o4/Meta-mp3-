package com.whitetea.baretrack.data;

import android.content.Context;
import android.content.SharedPreferences;

import com.whitetea.baretrack.model.Song;
import com.whitetea.baretrack.model.SongTags;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Iterator;

public final class SongStore {
    private static final String PREFS = "baretrack_library";
    private static final String KEY = "songs";
    private final SharedPreferences prefs;

    public SongStore(Context context) {
        prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    public synchronized ArrayList<Song> all() {
        ArrayList<Song> songs = new ArrayList<>();
        try {
            JSONArray array = new JSONArray(prefs.getString(KEY, "[]"));
            for (int i = 0; i < array.length(); i++) {
                JSONObject item = array.optJSONObject(i);
                if (item == null) continue;
                String id = item.optString("id", "");
                if (id.isEmpty()) continue;
                SongTags tags = new SongTags();
                JSONObject values = item.optJSONObject("values");
                if (values != null) {
                    Iterator<String> keys = values.keys();
                    while (keys.hasNext()) {
                        String key = keys.next();
                        tags.set(key, values.optString(key, ""));
                    }
                }
                JSONObject custom = item.optJSONObject("custom");
                if (custom != null) {
                    Iterator<String> keys = custom.keys();
                    while (keys.hasNext()) {
                        String key = keys.next();
                        tags.setCustom(key, custom.optString(key, ""));
                    }
                }
                songs.add(new Song(id, tags, item.optString("source", "")));
            }
        } catch (Exception ignored) { }
        return songs;
    }

    public synchronized void add(Song song) {
        ArrayList<Song> songs = all();
        songs.add(song);
        save(songs);
    }

    public synchronized void update(Song changed) {
        ArrayList<Song> songs = all();
        for (int i = 0; i < songs.size(); i++) {
            if (songs.get(i).id().equals(changed.id())) {
                songs.set(i, changed);
                break;
            }
        }
        save(songs);
    }

    public synchronized void remove(String id) {
        ArrayList<Song> songs = all();
        for (int i = songs.size() - 1; i >= 0; i--) if (songs.get(i).id().equals(id)) songs.remove(i);
        save(songs);
    }

    private void save(ArrayList<Song> songs) {
        JSONArray array = new JSONArray();
        for (Song song : songs) {
            JSONObject item = new JSONObject();
            JSONObject values = new JSONObject();
            JSONObject custom = new JSONObject();
            try {
                item.put("id", song.id());
                item.put("source", song.sourceUri());
                for (String key : song.tags().values().keySet()) values.put(key, song.tags().get(key));
                for (String key : song.tags().custom().keySet()) custom.put(key, song.tags().custom().get(key));
                item.put("values", values);
                item.put("custom", custom);
                array.put(item);
            } catch (Exception ignored) { }
        }
        prefs.edit().putString(KEY, array.toString()).commit();
    }
}
