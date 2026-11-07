package com.whitetea.baretrack.forensics;

import java.io.RandomAccessFile;
import java.util.ArrayList;
import java.util.List;

/** Shared state for one examination run. */
final class Scan {
    final ForensicReport report;
    final RandomAccessFile file;
    final long length;
    final TextForensics text;
    final ImageInspector images;
    final List<C2paInspector.Result> c2pa = new ArrayList<>();
    /** Byte ranges that hold the audio payload (used for the payload hash). */
    final List<long[]> payload = new ArrayList<>();
    String payloadKind = "";
    long audioEnd;
    // Cross-check values gathered by parsers
    int lameLowpassHz;
    int declaredBits;
    double declaredDurationSec = -1;
    double measuredDurationSec = -1;
    String encoderSummary = "";
    long lameFrames;
    long lameMusicLength;
    long oggRate;
    int oggPreSkip;

    Scan(ForensicReport report, RandomAccessFile file, long length) {
        this.report = report;
        this.file = file;
        this.length = length;
        this.audioEnd = length;
        this.text = new TextForensics(report);
        this.images = new ImageInspector(report, text);
    }

    void meta(String source, String key, String value, long offset) {
        if (value == null) return;
        String v = Bin.clean(value);
        if (v.isEmpty()) return;
        report.field(ForensicReport.SECTION_METADATA, source, key, v, offset);
        text.inspect(source, key, value, offset);
    }

    void encoder(String source, String key, String value, long offset) {
        if (value == null || value.trim().isEmpty()) return;
        report.field(ForensicReport.SECTION_ENCODER, source, key, value, offset);
    }

    void c2paStore(byte[] store, long offset, String source) {
        C2paInspector.Result r = C2paInspector.inspectStore(store, file, offset, report, source);
        if (r != null) c2pa.add(r);
    }
}
