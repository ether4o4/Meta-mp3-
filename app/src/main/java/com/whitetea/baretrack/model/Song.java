package com.whitetea.baretrack.model;

public final class Song {
    private final String id;
    private final SongTags tags;
    private final String sourceUri;
    private final String extension;

    public Song(String id, SongTags tags) { this(id, tags, "", "mp3"); }

    public Song(String id, SongTags tags, String sourceUri) {
        this(id, tags, sourceUri, "mp3");
    }

    public Song(String id, SongTags tags, String sourceUri, String extension) {
        this.id = id;
        this.tags = tags == null ? SongTags.blank() : tags;
        this.sourceUri = sourceUri == null ? "" : sourceUri;
        this.extension = "wav".equalsIgnoreCase(extension) ? "wav" : "mp3";
    }

    public String id() { return id; }
    public SongTags tags() { return tags; }
    public String sourceUri() { return sourceUri; }
    public String extension() { return extension; }
    public boolean isWave() { return "wav".equals(extension); }
    public String mimeType() { return isWave() ? "audio/wav" : "audio/mpeg"; }
    public String fileName() { return id + "." + extension; }
    public String displayTitle(int index) {
        String title = tags.get("Title");
        return title.isEmpty() ? "Untitled track " + (index + 1) : title;
    }
    public String displayArtist() {
        String artist = tags.get("Artist");
        return artist.isEmpty() ? "No artist set" : artist;
    }
}
