package com.whitetea.baretrack.forensics;

/** One finding, ranked by how much weight it can carry in an attribution decision. */
public final class Evidence {
    public enum Tier {
        CONFIRMED("Confirmed attribution"),
        PROBABLE("Probable attribution"),
        SUPPORTING("Supporting clue"),
        INCONCLUSIVE("Inconclusive"),
        INFO("Observation");

        public final String label;
        Tier(String label) { this.label = label; }
    }

    public final Tier tier;
    public final String category;
    public final String title;
    public final String detail;
    public final long offset;

    public Evidence(Tier tier, String category, String title, String detail, long offset) {
        this.tier = tier;
        this.category = category;
        this.title = title;
        this.detail = detail == null ? "" : detail;
        this.offset = offset;
    }
}
