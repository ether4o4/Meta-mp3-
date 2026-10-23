package com.whitetea.baretrack.model;

public final class Song {
    private final String id;
    private final SongTags tags;
    private final String sourceUri;

    public Song(String id, SongTags tags) { this(id, tags, ""); }

    public Song(String id, SongTags tags, String sourceUri) {
        this.id = id;
        this.tags = tags == null ? SongTags.blank() : tags;
        this.sourceUri = sourceUri == null ? "" : sourceUri;
    }

    public String id() { return id; }
    public SongTags tags() { return tags; }
    public String sourceUri() { return sourceUri; }
    public String fileName() { return id + ".mp3"; }
    public String displayTitle(int index) {
        String title = tags.get("Title");
        return title.isEmpty() ? "Untitled track " + (index + 1) : title;
    }
    public String displayArtist() {
        String artist = tags.get("Artist");
        return artist.isEmpty() ? "No artist set" : artist;
    }
}
