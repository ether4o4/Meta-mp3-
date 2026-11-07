package com.whitetea.baretrack.forensics;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Seven-part read-only audio provenance examination:
 * container dissection, complete metadata extraction, C2PA verification, encoder identification,
 * audio-signal examination, cross-platform fingerprint comparison, and a tiered evidence report.
 */
public final class AudioForensics {
    public static final String SUNO_VERIFIER = "https://suno.com/suno-credentials";

    public static final class Options {
        public PcmAudio.Provider decoder;
        public List<Fingerprint.Reference> references = new ArrayList<>();
        public boolean signal = true;
        public int maxSignalSeconds = 120;
        /** Details from the document provider (the copy being examined may not keep them). */
        public String providerName;
        public long providerSize = -1;
        public long providerModified = -1;
        public String providerMime;
    }

    public interface Progress { void update(String stage); }

    private AudioForensics() {}

    public static ForensicReport examine(File file, Options options, Progress progress) throws IOException {
        if (file == null || !file.isFile()) throw new IOException("Select a readable audio file first.");
        if (options == null) options = new Options();
        long started = System.currentTimeMillis();
        ForensicReport report = new ForensicReport();
        report.fileName = options.providerName != null ? options.providerName : file.getName();
        report.fileSize = file.length();

        step(progress, "Hashing");
        hashes(file, report);
        fileInfo(report, options);

        try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
            Scan s = new Scan(report, raf, raf.length());
            step(progress, "Dissecting container");
            dissect(s);
            step(progress, "Scanning raw bytes for identifiers");
            s.text.scanRaw(raf, s.length);
            payloadHash(s);
            step(progress, "Evaluating content credentials");
            evaluateC2pa(s, options);
            crossChecks(s);
            if (options.signal) {
                step(progress, "Decoding audio for signal analysis");
                signal(s, file, options);
            }
            step(progress, "Comparing fingerprints");
            compare(s, options);
            limitations(s);
        }
        report.elapsedMs = System.currentTimeMillis() - started;
        return report;
    }

    private static void step(Progress p, String stage) { if (p != null) p.update(stage); }

    private static void hashes(File file, ForensicReport r) throws IOException {
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
            MessageDigest md5 = MessageDigest.getInstance("MD5");
            byte[] buf = new byte[256 * 1024];
            try (InputStream in = new FileInputStream(file)) {
                int n;
                while ((n = in.read(buf)) != -1) {
                    sha256.update(buf, 0, n);
                    sha1.update(buf, 0, n);
                    md5.update(buf, 0, n);
                }
            }
            r.sha256 = Bin.hex(sha256.digest());
            r.sha1 = Bin.hex(sha1.digest());
            r.md5 = Bin.hex(md5.digest());
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IOException("Hash algorithms are unavailable on this device.", e);
        }
    }

    private static void fileInfo(ForensicReport r, Options o) {
        if (o.providerName != null) r.field(ForensicReport.SECTION_FILE, "Document provider", "Display name", o.providerName, -1);
        if (o.providerMime != null) r.field(ForensicReport.SECTION_FILE, "Document provider", "Reported MIME type", o.providerMime, -1);
        if (o.providerSize >= 0) {
            r.field(ForensicReport.SECTION_FILE, "Document provider", "Reported size", o.providerSize + " bytes", -1);
            if (o.providerSize != r.fileSize) {
                r.evidence(Evidence.Tier.INFO, "File", "Provider-reported size differs from the bytes read",
                        o.providerSize + " vs " + r.fileSize + " bytes.", -1);
            }
        }
        if (o.providerModified > 0) {
            java.text.SimpleDateFormat f = new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss 'UTC'", Locale.ROOT);
            f.setTimeZone(java.util.TimeZone.getTimeZone("UTC"));
            r.field(ForensicReport.SECTION_FILE, "Document provider", "Last modified", f.format(new java.util.Date(o.providerModified)), -1);
            r.evidence(Evidence.Tier.INCONCLUSIVE, "File", "Filesystem timestamp describes this copy only",
                    "Last modified " + f.format(new java.util.Date(o.providerModified)) + ". Timestamps change on download, copy and sync; they do not date the music.", -1);
        }
        String name = r.fileName.toLowerCase(Locale.ROOT);
        if (name.matches(".*[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}.*")) {
            r.evidence(Evidence.Tier.INCONCLUSIVE, "File", "File name contains a UUID",
                    "Some services name downloads by generation ID. Names are trivially changed, so this is a weak clue.", -1);
        }
        if (name.contains("suno") || name.contains("udio")) {
            r.evidence(Evidence.Tier.INCONCLUSIVE, "File", "File name mentions a generator", r.fileName, -1);
        }
    }

    // ---------------- 1. container dissection & 2. metadata ----------------

    private static void dissect(Scan s) throws IOException {
        ForensicReport r = s.report;
        long pos = 0;
        int tags = 0;
        while (tags < 8) {
            long used = Id3v2Parser.parse(s, pos, 0, tags == 0 ? "" : "stacked tag " + (tags + 1));
            if (used <= 0) break;
            pos += used;
            tags++;
        }
        if (tags > 1) r.evidence(Evidence.Tier.INFO, "Container", tags + " stacked ID3v2 tags at the start",
                "Multiple leading tags usually mean a second tool added its own tag without merging.", 0);
        // Skip zero padding some tools leave after ID3v2.
        byte[] head = Bin.read(s.file, pos, 16);
        if (head.length >= 4 && head[0] == 0 && tags > 0) {
            long q = pos;
            byte[] probe = Bin.read(s.file, q, 64 * 1024);
            int z = 0;
            while (z < probe.length && probe[z] == 0) z++;
            if (z > 0 && z < probe.length) {
                r.node(0, "Zero padding after ID3v2", pos, z, "");
                pos += z;
                head = Bin.read(s.file, pos, 16);
            }
        }
        long end = TailTags.parse(s, s.length);
        s.audioEnd = end;
        if (head.length >= 4 && Bin.ascii(head, 0, "fLaC")) FlacOggParser.flac(s, pos, end);
        else if (head.length >= 4 && Bin.ascii(head, 0, "OggS")) FlacOggParser.ogg(s, pos, end);
        else if (head.length >= 12 && (Bin.ascii(head, 0, "RIFF") || Bin.ascii(head, 0, "RIFX") || Bin.ascii(head, 0, "RF64") || Bin.ascii(head, 0, "BW64"))) IffParser.parse(s, pos, end);
        else if (head.length >= 12 && Bin.ascii(head, 0, "FORM")) IffParser.parse(s, pos, end);
        else if (head.length >= 8 && Bin.ascii(head, 4, "ftyp")) Mp4Parser.parse(s, pos, end);
        else if (head.length >= 4 && Bin.ascii(head, 0, "MAC ")) generic(s, pos, end, "Monkey's Audio (APE)");
        else if (head.length >= 4 && Bin.ascii(head, 0, "wvpk")) generic(s, pos, end, "WavPack");
        else if (head.length >= 4 && Bin.ascii(head, 0, "caff")) generic(s, pos, end, "Apple CAF");
        else if (head.length >= 2 && (head[0] & 0xFF) == 0xFF && (head[1] & 0xF6) == 0xF0) generic(s, pos, end, "AAC ADTS stream");
        else if (MpegStreamParser.looksLikeMpeg(s, pos, end)) {
            r.container = tags > 0 ? "MPEG audio with ID3v2" : "MPEG audio";
            MpegStreamParser.parse(s, pos, end);
        } else generic(s, pos, end, "Unrecognised format");
        if (r.container.equals("Unknown") && tags > 0) r.container = "ID3v2-tagged data";
    }

    private static void generic(Scan s, long start, long end, String name) throws IOException {
        s.report.container = name;
        s.report.node(0, name + " payload", start, end - start, "not dissected further by this build");
        s.payload.add(new long[] {start, end});
        s.payloadKind = name;
        byte[] probe = Bin.read(s.file, start, (int) Math.min(end - start, 8 << 20));
        int at = C2paInspector.findStore(probe);
        if (at >= 0) s.c2paStore(java.util.Arrays.copyOfRange(probe, at, probe.length), start + at, name);
    }

    private static void payloadHash(Scan s) throws IOException {
        if (!s.report.audioPayloadSha256.isEmpty() || s.payload.isEmpty()) return;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] buf = new byte[256 * 1024];
            long total = 0;
            for (long[] range : s.payload) {
                long from = range[0], to = Math.min(range[1], s.length);
                s.file.seek(from);
                long left = to - from;
                while (left > 0) {
                    int n = (int) Math.min(buf.length, left);
                    s.file.readFully(buf, 0, n);
                    md.update(buf, 0, n);
                    left -= n;
                }
                total += to - from;
            }
            s.report.audioPayloadSha256 = Bin.hex(md.digest());
            s.report.audioPayloadNote = "(SHA-256 of " + total + " bytes of " + s.payloadKind + " — unaffected by tag changes)";
        } catch (java.security.NoSuchAlgorithmException ignored) { }
    }

    // ---------------- 3. C2PA ----------------

    private static void evaluateC2pa(Scan s, Options o) {
        ForensicReport r = s.report;
        if (s.c2pa.isEmpty()) {
            r.field(ForensicReport.SECTION_C2PA, "Search", "Result", "No C2PA manifest store found in any known carrier "
                    + "(ID3 GEOB, RIFF C2PA chunk, MP4 uuid box, FLAC APPLICATION, unreferenced bytes).", -1);
            r.evidence(Evidence.Tier.INCONCLUSIVE, "C2PA", "No content credential in this copy",
                    "Credentials only exist on newer downloads and are lost when a file is re-encoded or re-saved by most tools. "
                            + "Absence is not evidence of origin either way.", -1);
            return;
        }
        C2paInspector.Result c = s.c2pa.get(s.c2pa.size() - 1);
        r.c2pa = c;
        r.fingerprint.put("c2pa.generator", c.claimGenerator);
        r.fingerprint.put("c2pa.issuer", c.issuer);
        r.fingerprint.put("c2pa.signer.sha256", c.signerSha256);
        if (!c.softBinding.isEmpty()) r.fingerprint.put("c2pa.softBinding", c.softBinding);
        String who = c.namesSuno() ? "Suno" : (c.claimGenerator.isEmpty() ? "an unnamed generator" : c.claimGenerator);
        String summary = "Generator: " + (c.claimGenerator.isEmpty() ? "(none)" : c.claimGenerator)
                + "\nSigner: " + (c.signer.isEmpty() ? "(none)" : c.signer)
                + "\nIssuer: " + (c.issuer.isEmpty() ? "(none)" : c.issuer)
                + "\nSignature: " + c.signatureStatus
                + "\nAssertion hashes: " + c.assertionHashStatus
                + "\nContent binding: " + c.bindingStatus
                + (c.digitalSourceType.isEmpty() ? "" : "\nDeclared source type: " + c.digitalSourceType)
                + (c.actions.isEmpty() ? "" : "\nActions: " + c.actions)
                + "\nConfirm with the official verifier: " + SUNO_VERIFIER;

        Fingerprint.Reference pinned = null;
        for (Fingerprint.Reference ref : o.references) {
            String sig = ref.fingerprint.get("c2pa.signer.sha256");
            if (sig != null && sig.equalsIgnoreCase(c.signerSha256)) pinned = ref;
        }
        if (c.intact() && pinned != null) {
            r.evidence(Evidence.Tier.CONFIRMED, "C2PA", "Valid signed C2PA credential from " + who + ", signed by the certificate you pinned in '" + pinned.label + "'",
                    summary + "\nThe signer certificate is identical to the one in your verified reference, the signature is valid, "
                            + "and the audio bytes are unchanged since signing.", -1);
        } else if (c.intact()) {
            r.evidence(Evidence.Tier.PROBABLE, "C2PA", "Cryptographically intact C2PA credential naming " + who,
                    summary + "\nSignature and content binding verify offline. Signer identity is not trust-list checked here — "
                            + "run the official verifier, then save this file as a reference to pin the signer.", -1);
        } else if (Boolean.TRUE.equals(c.signatureValid) && Boolean.FALSE.equals(c.bindingValid)) {
            r.evidence(Evidence.Tier.PROBABLE, "C2PA", "Signed credential naming " + who + ", but the audio changed after signing",
                    summary + "\nThe credential is authentic but no longer matches these bytes (edited, re-tagged within the "
                            + "hashed region, or truncated). It still records where the original came from.", -1);
        } else if (Boolean.TRUE.equals(c.signatureValid)) {
            r.evidence(Evidence.Tier.PROBABLE, "C2PA", "Valid C2PA signature naming " + who + " (content binding not checked)", summary, -1);
        } else if (Boolean.FALSE.equals(c.signatureValid)) {
            r.evidence(c.namesSuno() ? Evidence.Tier.SUPPORTING : Evidence.Tier.INCONCLUSIVE, "C2PA", "C2PA credential present but its signature does not verify",
                    summary + "\nAn invalid signature can mean tampering or an unsupported variant; treat the claims as unverified.", -1);
        } else {
            r.evidence(c.namesSuno() ? Evidence.Tier.PROBABLE : Evidence.Tier.SUPPORTING, "C2PA", "C2PA credential naming " + who + " (signature not verifiable on this device)", summary, -1);
        }
        if (c.aiDeclared()) {
            r.evidence(Evidence.Tier.PROBABLE, "AI declaration", "Credential declares AI-generated content",
                    "digitalSourceType = " + c.digitalSourceType + (Boolean.TRUE.equals(c.signatureValid) ? " (inside a validly signed claim)" : " (claim not verified)"), -1);
        }
        if (!c.softBinding.isEmpty()) {
            r.evidence(c.softBinding.toLowerCase(Locale.ROOT).contains("suno") ? Evidence.Tier.PROBABLE : Evidence.Tier.SUPPORTING, "Fingerprint",
                    "Soft-binding (watermark/fingerprint) algorithm '" + c.softBinding + "'",
                    "A soft binding ties the credential to the audio signal itself, so it can survive re-encoding. "
                            + "Its value can only be checked by the issuer.", -1);
        }
    }

    // ---------------- 4. cross checks ----------------

    private static void crossChecks(Scan s) {
        ForensicReport r = s.report;
        if (s.declaredDurationSec > 0 && s.measuredDurationSec > 0 && Math.abs(s.declaredDurationSec - s.measuredDurationSec) > 2) {
            r.evidence(Evidence.Tier.SUPPORTING, "Edit history", "Tagged length does not match the audio",
                    String.format(Locale.ROOT, "TLEN says %.1f s, the stream is %.1f s. The tag was copied from a different version of the track.",
                            s.declaredDurationSec, s.measuredDurationSec), -1);
        }
        String enc = s.encoderSummary.toLowerCase(Locale.ROOT);
        String tagEnc = r.fingerprint.get("id3.encoderTag");
        if (tagEnc != null && !enc.isEmpty()) {
            String t = tagEnc.toLowerCase(Locale.ROOT);
            boolean ffmpegTag = t.startsWith("lavf") || t.contains("ffmpeg");
            boolean lameStream = enc.startsWith("lame");
            String note = ffmpegTag && lameStream ? "FFmpeg (libavformat) muxed a LAME-encoded stream — the usual output of `ffmpeg -c:a libmp3lame`."
                    : ffmpegTag && enc.startsWith("lavc") ? "FFmpeg both encoded and tagged this file."
                    : "Tag says \"" + tagEnc + "\", stream header says \"" + s.encoderSummary + "\".";
            r.field(ForensicReport.SECTION_ENCODER, "Cross-check", "Tag vs. stream encoder", note, -1);
        }
        if (!s.encoderSummary.isEmpty()) {
            r.evidence(Evidence.Tier.SUPPORTING, "Encoder", "Encoding pipeline: " + s.encoderSummary,
                    "Encoder identity narrows down the export tool; it rarely identifies a particular website by itself.", -1);
        }
    }

    // ---------------- 5. signal ----------------

    private static void signal(Scan s, File file, Options o) {
        ForensicReport r = s.report;
        PcmAudio pcm = null;
        String reason = "";
        try {
            pcm = PcmAudio.readPcm(file, o.maxSignalSeconds);
            if (pcm == null && o.decoder != null) pcm = o.decoder.decode(file, o.maxSignalSeconds);
            if (pcm == null) reason = o.decoder == null ? "no decoder available for this format in this environment" : "the decoder returned no audio";
        } catch (Throwable e) {
            reason = "decoding failed: " + (e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage());
        }
        if (pcm == null) {
            r.field(ForensicReport.SECTION_SIGNAL, "Signal", "Status", "not analysed — " + reason, -1);
            r.limitation("Signal analysis was skipped: " + reason + ".");
            return;
        }
        try {
            SignalAnalyzer.analyze(s, pcm);
        } catch (Throwable e) {
            r.field(ForensicReport.SECTION_SIGNAL, "Signal", "Status", "analysis error: " + e.getClass().getSimpleName(), -1);
        }
    }

    // ---------------- 6. comparison ----------------

    private static void compare(Scan s, Options o) {
        ForensicReport r = s.report;
        if (o.references.isEmpty()) {
            r.field(ForensicReport.SECTION_COMPARE, "References", "Status",
                    "No reference profiles saved. Examine a file whose origin you have verified (e.g. a fresh Suno download "
                            + "confirmed by the official verifier, a Udio download, or your own DAW export) and save it as a reference.", -1);
        }
        Fingerprint.Comparison best = null;
        for (Fingerprint.Reference ref : o.references) {
            Fingerprint.Comparison c = r.fingerprint.compareTo(ref);
            r.field(ForensicReport.SECTION_COMPARE, "Reference '" + ref.label + "'", "Agreement",
                    c.percent + "% (" + c.matchedWeight + "/" + c.totalWeight + " weighted)", -1);
            if (!c.matched.isEmpty()) r.field(ForensicReport.SECTION_COMPARE, "Reference '" + ref.label + "'", "Matching traits", Bin.join(", ", c.matched), -1);
            if (!c.differed.isEmpty()) r.field(ForensicReport.SECTION_COMPARE, "Reference '" + ref.label + "'", "Differing traits", Bin.join("; ", c.differed), -1);
            if (best == null || c.percent > best.percent) best = c;
        }
        if (best != null && best.totalWeight >= 8) {
            if (best.percent >= 85) {
                r.evidence(Evidence.Tier.SUPPORTING, "Export fingerprint", "Export fingerprint matches reference '" + best.reference.label + "' (" + best.percent + "%)",
                        "Matching: " + Bin.join(", ", best.matched) + ". A matching export pipeline is consistent with the same source, "
                                + "but other tools configured the same way would match too.", -1);
            } else if (best.percent >= 60) {
                r.evidence(Evidence.Tier.INCONCLUSIVE, "Export fingerprint", "Partial match to reference '" + best.reference.label + "' (" + best.percent + "%)",
                        "Differences: " + Bin.join("; ", best.differed), -1);
            }
        }
        for (java.util.Map.Entry<String, String> e : r.fingerprint.features().entrySet()) {
            r.field(ForensicReport.SECTION_COMPARE, "This file's fingerprint", e.getKey(), e.getValue(), -1);
        }
    }

    private static void limitations(Scan s) {
        ForensicReport r = s.report;
        r.limitation("Marker and string matches are leads; only a validly signed credential can attribute origin cryptographically.");
        r.limitation("C2PA signer identity is not checked against the C2PA or Suno trust lists offline, and revocation is not checked. "
                + "Use the official verifier (" + SUNO_VERIFIER + ") for that, then pin the signer by saving the file as a reference.");
        r.limitation("Missing metadata or credentials do not show that a track is human-made or from any particular service; "
                + "credentials only exist on newer downloads and most editors discard them.");
        r.limitation("Signal measurements describe the sound. No generic detector can establish that a track came from Suno, "
                + "and proprietary audio watermarks are not decoded.");
        r.limitation("Filesystem timestamps and names describe this copy, not when the music was created.");
        r.limitation("The examined file was opened read-only; nothing was modified.");
    }
}
