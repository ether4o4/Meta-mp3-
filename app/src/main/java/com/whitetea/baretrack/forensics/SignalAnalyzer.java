package com.whitetea.baretrack.forensics;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Characteristics of the sound itself: level, spectrum and band-limit, stereo/phase, transients,
 * repetition and stationary narrowband components. These describe the signal; they do not by themselves
 * establish that audio is AI-generated, and no proprietary watermark is decoded.
 */
final class SignalAnalyzer {
    private static final int N = 4096;
    private static final String SRC = "Signal";

    private SignalAnalyzer() {}

    static void analyze(Scan s, PcmAudio pcm) {
        ForensicReport r = s.report;
        int sr = pcm.sampleRate, n = pcm.frames;
        if (n < N * 4 || sr <= 0) {
            r.field(ForensicReport.SECTION_SIGNAL, SRC, "Status", "too short for analysis", -1);
            return;
        }
        float[] l = pcm.channels[0];
        float[] rch = pcm.channels.length > 1 ? pcm.channels[1] : null;
        put(r, "Decoder", pcm.decoder);
        put(r, "Analysed", String.format(Locale.ROOT, "%.1f s at %d Hz, %d channel(s)%s", n / (double) sr, sr, pcm.channels.length,
                pcm.truncated ? " (first part of the file only)" : ""));

        levels(s, pcm);
        bitDepth(s, pcm);
        if (rch != null) stereo(s, l, rch, sr);
        spectrum(s, pcm);
        transients(s, pcm);
        repetition(s, pcm);
    }

    private static void put(ForensicReport r, String k, String v) { r.field(ForensicReport.SECTION_SIGNAL, SRC, k, v, -1); }

    private static double db(double x) { return 20 * Math.log10(Math.max(x, 1e-12)); }

    // ---- level ----

    private static void levels(Scan s, PcmAudio pcm) {
        ForensicReport r = s.report;
        StringBuilder dc = new StringBuilder();
        double peak = 0, sumSq = 0;
        long clipped = 0, runs = 0, silent = 0, total = 0;
        for (float[] c : pcm.channels) {
            double sum = 0;
            boolean inRun = false;
            for (int i = 0; i < pcm.frames; i++) {
                float v = c[i];
                double a = Math.abs(v);
                sum += v;
                sumSq += v * (double) v;
                if (a > peak) peak = a;
                if (a >= 0.9999) { clipped++; if (!inRun) { runs++; inRun = true; } } else inRun = false;
                if (a < 1e-4) silent++;
                total++;
            }
            if (dc.length() > 0) dc.append(", ");
            dc.append(String.format(Locale.ROOT, "%.6f", sum / pcm.frames));
        }
        double rms = Math.sqrt(sumSq / total);
        put(r, "Peak", String.format(Locale.ROOT, "%.2f dBFS", db(peak)));
        put(r, "RMS", String.format(Locale.ROOT, "%.2f dBFS", db(rms)));
        put(r, "Crest factor", String.format(Locale.ROOT, "%.2f dB", db(peak) - db(rms)));
        put(r, "DC offset per channel", dc.toString());
        put(r, "Clipped samples", clipped + " in " + runs + " run(s)");
        put(r, "Near-silent samples", String.format(Locale.ROOT, "%.2f%%", 100.0 * silent / total));
        if (runs > 50) r.evidence(Evidence.Tier.INFO, "Signal", "Heavy clipping (" + runs + " clipped runs)", "Typical of loud masters or aggressive limiting.", -1);
    }

    private static void bitDepth(Scan s, PcmAudio pcm) {
        if (pcm.effectiveBits <= 0 || pcm.containerBits <= 0) return;
        put(s.report, "Effective bit depth", pcm.effectiveBits + " of " + pcm.containerBits + " container bits carry data");
        if (pcm.effectiveBits < pcm.containerBits - 1) {
            s.report.evidence(Evidence.Tier.SUPPORTING, "Export pipeline", "Padded bit depth: " + pcm.effectiveBits + "-bit audio in a " + pcm.containerBits + "-bit file",
                    "The lowest " + (pcm.containerBits - pcm.effectiveBits) + " bits are always zero, so the audio was produced at lower resolution and converted up.", -1);
        }
        s.report.fingerprint.put("signal.effectiveBits", Integer.toString(pcm.effectiveBits));
    }

    // ---- stereo & phase ----

    private static void stereo(Scan s, float[] l, float[] r, int sr) {
        ForensicReport rep = s.report;
        int n = l.length;
        double sl = 0, sr2 = 0, slr = 0, mid = 0, side = 0;
        long identical = 0;
        for (int i = 0; i < n; i++) {
            double a = l[i], b = r[i];
            sl += a * a; sr2 += b * b; slr += a * b;
            double m = (a + b) / 2, d = (a - b) / 2;
            mid += m * m; side += d * d;
            if (l[i] == r[i]) identical++;
        }
        double corr = slr / Math.sqrt(Math.max(sl * sr2, 1e-20));
        put(rep, "L/R correlation", String.format(Locale.ROOT, "%.4f", corr));
        put(rep, "Side/mid energy", side < 1e-12 ? "no side signal (mono content)" : String.format(Locale.ROOT, "%.2f dB", 10 * Math.log10(side / Math.max(mid, 1e-20))));
        put(rep, "L/R balance", String.format(Locale.ROOT, "%.2f dB", 10 * Math.log10(Math.max(sl, 1e-20) / Math.max(sr2, 1e-20))));
        double identicalPct = 100.0 * identical / n;
        put(rep, "Identical L/R samples", String.format(Locale.ROOT, "%.2f%%", identicalPct));
        if (identicalPct > 99.9) rep.evidence(Evidence.Tier.INFO, "Signal", "Dual-mono: both channels are identical", "Stereo file carrying a mono signal.", -1);
        if (corr < -0.5) rep.evidence(Evidence.Tier.SUPPORTING, "Signal", "Channels are largely out of phase (correlation " + String.format(Locale.ROOT, "%.2f", corr) + ")",
                "One channel is likely polarity-inverted; this collapses in mono.", -1);

        // Per-band correlation and mean inter-channel phase difference via cross-spectra.
        double[] edges = {20, 250, 2000, 6000, 12000, sr / 2.0};
        String[] names = {"low <250 Hz", "low-mid 250–2k", "mid 2–6k", "high 6–12k", "air >12k"};
        double[] cross = new double[5], pl = new double[5], pr = new double[5], phase = new double[5], weight = new double[5];
        float[] win = hann(N);
        double[] lr = new double[N], li = new double[N], rr = new double[N], ri = new double[N];
        int hops = Math.min(400, (n - N) / N);
        int step = Math.max(N, (n - N) / Math.max(1, hops));
        for (int start = 0; start + N <= n; start += step) {
            for (int i = 0; i < N; i++) { lr[i] = l[start + i] * win[i]; li[i] = 0; rr[i] = r[start + i] * win[i]; ri[i] = 0; }
            Fft.transform(lr, li);
            Fft.transform(rr, ri);
            for (int k = 1; k < N / 2; k++) {
                double f = k * (double) sr / N;
                int band = -1;
                for (int b = 0; b < 5; b++) if (f >= edges[b] && f < edges[b + 1]) band = b;
                if (band < 0) continue;
                double re = lr[k] * rr[k] + li[k] * ri[k];
                double im = li[k] * rr[k] - lr[k] * ri[k];
                double ml = lr[k] * lr[k] + li[k] * li[k], mr = rr[k] * rr[k] + ri[k] * ri[k];
                cross[band] += re;
                pl[band] += ml;
                pr[band] += mr;
                double w = Math.sqrt(ml * mr);
                phase[band] += Math.abs(Math.atan2(im, re)) * w;
                weight[band] += w;
            }
        }
        StringBuilder bands = new StringBuilder(), phases = new StringBuilder();
        for (int b = 0; b < 5; b++) {
            if (pl[b] <= 0 || pr[b] <= 0) continue;
            if (bands.length() > 0) { bands.append(" · "); phases.append(" · "); }
            bands.append(names[b]).append(String.format(Locale.ROOT, " %.2f", cross[b] / Math.sqrt(pl[b] * pr[b])));
            phases.append(names[b]).append(String.format(Locale.ROOT, " %.0f°", Math.toDegrees(phase[b] / Math.max(weight[b], 1e-20))));
        }
        put(rep, "Per-band correlation", bands.toString());
        put(rep, "Mean inter-channel phase difference", phases.toString());
    }

    // ---- spectrum, band limit, tonal components ----

    private static void spectrum(Scan s, PcmAudio pcm) {
        ForensicReport r = s.report;
        int sr = pcm.sampleRate, n = pcm.frames, bins = N / 2;
        float[] mono = mono(pcm);
        float[] win = hann(N);
        double[] re = new double[N], im = new double[N];
        double[] avg = new double[bins];
        int frames = 0;
        int maxFrames = 600;
        int step = Math.max(N, (n - N) / maxFrames);
        List<double[]> highFrames = new ArrayList<>();
        int hiStart = (int) (12000.0 * N / sr);
        List<Double> cutoffs = new ArrayList<>();
        for (int start = 0; start + N <= n; start += step) {
            double energy = 0;
            for (int i = 0; i < N; i++) { re[i] = mono[start + i] * win[i]; im[i] = 0; energy += re[i] * re[i]; }
            if (energy < 1e-8) continue;
            Fft.transform(re, im);
            double[] frame = hiStart < bins ? new double[bins - hiStart] : null;
            double[] pw = new double[bins];
            for (int k = 0; k < bins; k++) {
                double p = re[k] * re[k] + im[k] * im[k];
                avg[k] += p;
                pw[k] = p;
                if (frame != null && k >= hiStart) frame[k - hiStart] = p;
            }
            if (frame != null && highFrames.size() < 300) highFrames.add(frame);
            cutoffs.add(cutoff(pw, sr));
            frames++;
        }
        if (frames == 0) { put(r, "Spectrum", "signal is silent"); return; }
        for (int k = 0; k < bins; k++) avg[k] /= frames;

        double total = 0, weighted = 0;
        for (int k = 1; k < bins; k++) { total += avg[k]; weighted += avg[k] * k * sr / (double) N; }
        double centroid = weighted / Math.max(total, 1e-20);
        put(r, "Spectral centroid", String.format(Locale.ROOT, "%.0f Hz", centroid));
        double acc = 0;
        double r85 = 0, r95 = 0, r99 = 0;
        for (int k = 1; k < bins; k++) {
            acc += avg[k];
            double f = k * sr / (double) N;
            if (r85 == 0 && acc >= 0.85 * total) r85 = f;
            if (r95 == 0 && acc >= 0.95 * total) r95 = f;
            if (r99 == 0 && acc >= 0.99 * total) r99 = f;
        }
        put(r, "Spectral rolloff 85/95/99%", String.format(Locale.ROOT, "%.0f / %.0f / %.0f Hz", r85, r95, r99));

        double[] edges = {0, 60, 250, 2000, 6000, 12000, 16000, sr / 2.0};
        String[] names = {"sub <60", "bass 60–250", "low-mid 250–2k", "presence 2–6k", "brilliance 6–12k", "12–16k", ">16k"};
        StringBuilder dist = new StringBuilder();
        for (int b = 0; b < names.length; b++) {
            double e = 0;
            for (int k = 1; k < bins; k++) { double f = k * sr / (double) N; if (f >= edges[b] && f < edges[b + 1]) e += avg[k]; }
            if (dist.length() > 0) dist.append(" · ");
            dist.append(names[b]).append(String.format(Locale.ROOT, " %.2f%%", 100 * e / Math.max(total, 1e-20)));
        }
        put(r, "Band energy distribution", dist.toString());

        double logSum = 0, linSum = 0;
        int cnt = 0;
        for (int k = 1; k < bins; k++) {
            double f = k * sr / (double) N;
            if (f < 1000 || f > 16000) continue;
            logSum += Math.log(Math.max(avg[k], 1e-20));
            linSum += avg[k];
            cnt++;
        }
        if (cnt > 0) put(r, "Spectral flatness 1–16 kHz", String.format(Locale.ROOT, "%.4f", Math.exp(logSum / cnt) / (linSum / cnt)));

        // Band limit: the highest frequency still within 50 dB of the 1–8 kHz reference level.
        double cut = cutoff(avg, sr);
        double steep = steepness(avg, sr, cut);
        put(r, "High-frequency cutoff", String.format(Locale.ROOT, "%.0f Hz (%.0f%% of Nyquist), level drop across it %.0f dB", cut, 100 * cut / (sr / 2.0), steep));
        double mean = 0, var = 0;
        for (double c : cutoffs) mean += c;
        mean /= cutoffs.size();
        for (double c : cutoffs) var += (c - mean) * (c - mean);
        double sd = Math.sqrt(var / cutoffs.size());
        put(r, "Cutoff stability across time", String.format(Locale.ROOT, "mean %.0f Hz, s.d. %.0f Hz over %d frames", mean, sd, cutoffs.size()));
        s.report.fingerprint.put("signal.cutoffHz", Fingerprint.bucket(cut, 500));
        boolean sharp = steep > 25 && cut < sr / 2.0 * 0.97;
        if (sharp) {
            String detail = "A brick-wall low-pass is characteristic of lossy encoders (MP3, AAC, Opus) and of band-limited "
                    + "generation pipelines.";
            if (s.lameLowpassHz > 0) {
                double diff = Math.abs(cut - s.lameLowpassHz);
                detail += String.format(Locale.ROOT, " The encoder header records a %d Hz low-pass; measured cutoff is %.0f Hz (%s).",
                        s.lameLowpassHz, cut, diff < 1200 ? "consistent" : "inconsistent — the audio was band-limited before this encode, e.g. a re-encode of an earlier lossy file");
                if (diff >= 1200 && cut < s.lameLowpassHz) {
                    r.evidence(Evidence.Tier.SUPPORTING, "Edit history", "Audio is band-limited below this file's own encoder low-pass",
                            String.format(Locale.ROOT, "Measured %.0f Hz vs. LAME low-pass %d Hz: this MP3 was most likely made from an already-lossy source (transcode).", cut, s.lameLowpassHz), -1);
                }
            }
            boolean lossless = s.payloadKind.startsWith("WAV") || s.payloadKind.startsWith("AIFF") || s.payloadKind.startsWith("FLAC");
            if (lossless) {
                r.evidence(Evidence.Tier.SUPPORTING, "Export pipeline", String.format(Locale.ROOT, "Lossless file with a lossy-style %.1f kHz brick-wall cutoff", cut / 1000),
                        "Lossless containers normally carry content up to Nyquist (" + sr / 2 + " Hz). A sharp cutoff means the audio passed "
                                + "through a lossy codec or a band-limited generator before being saved losslessly.", -1);
            } else {
                r.evidence(Evidence.Tier.INFO, "Signal", String.format(Locale.ROOT, "Brick-wall cutoff at %.1f kHz", cut / 1000), detail, -1);
            }
        }
        tonal(s, avg, highFrames, sr, hiStart);
    }

    private static double cutoff(double[] p, int sr) {
        int bins = p.length;
        int k1 = Math.max(1, (int) (1000.0 * N / sr)), k8 = Math.min(bins - 1, (int) (8000.0 * N / sr));
        double ref = 0;
        for (int k = k1; k <= k8; k++) ref += p[k];
        ref /= Math.max(1, k8 - k1 + 1);
        double threshold = ref * 1e-5; // −50 dB
        // Smooth over ~100 Hz to ignore isolated bins.
        int w = Math.max(1, (int) (100.0 * N / sr));
        for (int k = bins - 1 - w; k > k8; k--) {
            double sum = 0;
            for (int j = k - w; j <= k + w; j++) sum += p[j];
            if (sum / (2 * w + 1) > threshold) return k * sr / (double) N;
        }
        return k8 * sr / (double) N;
    }

    /** Level drop across the cutoff: mean of [cut−1.5k, cut−0.5k] vs mean of [cut+0.2k, cut+0.7k], in dB. */
    private static double steepness(double[] p, int sr, double cut) {
        double hzPerBin = sr / (double) N;
        int a0 = (int) ((cut - 1500) / hzPerBin), a1 = (int) ((cut - 500) / hzPerBin);
        int b0 = (int) ((cut + 200) / hzPerBin), b1 = (int) ((cut + 700) / hzPerBin);
        if (a0 < 1 || b1 >= p.length) return 0;
        double a = 0, b = 0;
        for (int j = a0; j <= a1; j++) a += p[j];
        for (int j = b0; j <= b1; j++) b += p[j];
        a /= (a1 - a0 + 1);
        b /= (b1 - b0 + 1);
        return 10 * Math.log10(Math.max(a, 1e-30) / Math.max(b, 1e-30));
    }

    /** Stationary narrowband peaks above 12 kHz: possible pilot tones, carriers or interference. */
    private static void tonal(Scan s, double[] avg, List<double[]> frames, int sr, int hiStart) {
        if (frames.size() < 20 || hiStart >= avg.length) return;
        List<String> found = new ArrayList<>();
        int radius = 24;
        for (int k = hiStart + radius; k < avg.length - radius; k++) {
            double[] neigh = new double[2 * radius];
            int q = 0;
            for (int j = k - radius; j < k + radius + 1; j++) if (Math.abs(j - k) > 2) neigh[q++] = avg[j];
            java.util.Arrays.sort(neigh, 0, q);
            double median = neigh[q / 2];
            if (median <= 0 || avg[k] < median * 30) continue; // ≥ 15 dB above surroundings
            if (avg[k] < avg[k - 1] || avg[k] < avg[k + 1]) continue;
            int present = 0;
            for (double[] f : frames) {
                int i = k - hiStart;
                double local = (f[Math.max(0, i - 8)] + f[Math.min(f.length - 1, i + 8)]) / 2;
                if (f[i] > local * 10) present++;
            }
            double ratio = present / (double) frames.size();
            if (ratio < 0.8) continue;
            double hz = k * sr / (double) N;
            found.add(String.format(Locale.ROOT, "%.0f Hz (+%.0f dB, present in %.0f%% of frames)", hz, 10 * Math.log10(avg[k] / median), ratio * 100));
            k += radius;
            if (found.size() >= 6) break;
        }
        if (found.isEmpty()) {
            put(s.report, "Stationary narrowband components >12 kHz", "none detected");
            return;
        }
        put(s.report, "Stationary narrowband components >12 kHz", Bin.join("; ", found));
        s.report.evidence(Evidence.Tier.SUPPORTING, "Possible watermark", "Persistent narrowband tone(s) in the high band",
                Bin.join("; ", found) + ". Constant tones at fixed high frequencies are not musical content. They can be watermark carriers, "
                        + "pilot tones, or electrical interference; this tool does not decode them.", -1);
    }

    // ---- transients ----

    private static void transients(Scan s, PcmAudio pcm) {
        int sr = pcm.sampleRate, n = pcm.frames, size = 1024, hop = 512;
        float[] mono = mono(pcm);
        float[] win = hann(size);
        double[] re = new double[size], im = new double[size], prev = new double[size / 2];
        int frames = (n - size) / hop;
        double[] flux = new double[frames];
        for (int f = 0; f < frames; f++) {
            int start = f * hop;
            for (int i = 0; i < size; i++) { re[i] = mono[start + i] * win[i]; im[i] = 0; }
            Fft.transform(re, im);
            double sum = 0;
            for (int k = 1; k < size / 2; k++) {
                double mag = Math.sqrt(re[k] * re[k] + im[k] * im[k]);
                double d = mag - prev[k];
                if (d > 0) sum += d;
                prev[k] = mag;
            }
            flux[f] = sum;
        }
        int onsets = 0;
        double strength = 0;
        int w = 8;
        for (int f = w; f < frames - w; f++) {
            double mean = 0;
            for (int j = f - w; j <= f + w; j++) mean += flux[j];
            mean /= (2 * w + 1);
            if (flux[f] > mean * 1.6 && flux[f] >= flux[f - 1] && flux[f] >= flux[f + 1] && flux[f] > 1e-3) {
                onsets++;
                strength += flux[f] / Math.max(mean, 1e-9);
            }
        }
        double seconds = n / (double) sr;
        put(s.report, "Onsets (spectral flux)", String.format(Locale.ROOT, "%d (%.2f per second), mean peak/local ratio %.2f",
                onsets, onsets / seconds, onsets == 0 ? 0 : strength / onsets));
    }

    // ---- repetition ----

    private static void repetition(Scan s, PcmAudio pcm) {
        ForensicReport r = s.report;
        int sr = pcm.sampleRate, n = pcm.frames;
        // 1) Bit-exact duplicate windows at any alignment (Rabin–Karp over the 16-bit mono view).
        int block = 2048;
        LongIntMap grid = new LongIntMap(Math.max(16, n / block * 2));
        final long base = 1000003L;
        long pow = 1;
        for (int i = 0; i < block - 1; i++) pow *= base;
        int considered = 0;
        for (int b = 0; b + block <= n; b += block) {
            long h = 0;
            long energy = 0;
            for (int i = b; i < b + block; i++) { h = h * base + (pcm.mono16[i] + 32768); energy += Math.abs(pcm.mono16[i]); }
            if (energy < block * 16L) continue;
            considered++;
            if (!grid.containsKey(h)) grid.put(h, b);
        }
        int dup = 0;
        long firstA = -1, firstB = -1;
        long h = 0, energy = 0;
        int lastCounted = -block;
        for (int i = 0; i < n; i++) {
            if (i >= block) {
                h -= pow * (pcm.mono16[i - block] + 32768);
                energy -= Math.abs(pcm.mono16[i - block]);
            }
            h = h * base + (pcm.mono16[i] + 32768);
            energy += Math.abs(pcm.mono16[i]);
            int start = i - block + 1;
            if (start < 0 || energy < block * 16L || start < lastCounted + block) continue;
            int at = grid.get(h);
            if (at >= 0 && start - at >= block && verifyEqual(pcm.mono16, at, start, block)) {
                dup++;
                lastCounted = start;
                if (firstA < 0) { firstA = at; firstB = start; }
            }
        }
        double dupSeconds = dup * block / (double) sr;
        put(r, "Bit-exact repeated audio", String.format(Locale.ROOT, "%d window(s) of %d samples (≈%.2f s) re-occur later in the analysed audio", dup, block, dupSeconds)
                + (firstA >= 0 ? String.format(Locale.ROOT, "; first: %.3f s also occurs at %.3f s", firstA / (double) sr, firstB / (double) sr) : "")
                + " (" + considered + " non-silent reference windows)");
        if (dup > 0 && pcm.decoder.contains("exact")) {
            r.evidence(Evidence.Tier.SUPPORTING, "Signal", String.format(Locale.ROOT, "Sample-identical repeated audio (≈%.1f s)", dupSeconds),
                    "Identical PCM indicates copy-pasted or looped material in the production or edit process"
                            + (firstA >= 0 ? String.format(Locale.ROOT, " — e.g. %.2f s reappears at %.2f s", firstA / (double) sr, firstB / (double) sr) : "") + ".", -1);
        }

        // 2) Near-identical segments from log band-energy features.
        int hop = 8192, bands = 24;
        int frames = (n - hop) / hop;
        if (frames < 40) return;
        float[] mono = mono(pcm);
        float[] win = hann(hop);
        double[] re = new double[hop], im = new double[hop];
        double[][] feat = new double[frames][bands];
        double lo = Math.log(60), hi = Math.log(Math.min(16000, sr / 2.0));
        for (int f = 0; f < frames; f++) {
            for (int i = 0; i < hop; i++) { re[i] = mono[f * hop + i] * win[i]; im[i] = 0; }
            Fft.transform(re, im);
            for (int k = 1; k < hop / 2; k++) {
                double hz = k * sr / (double) hop;
                if (hz < 60 || hz >= Math.exp(hi)) continue;
                int b = (int) ((Math.log(hz) - lo) / (hi - lo) * bands);
                if (b >= 0 && b < bands) feat[f][b] += re[k] * re[k] + im[k] * im[k];
            }
            double norm = 0;
            for (int b = 0; b < bands; b++) { feat[f][b] = Math.log10(feat[f][b] + 1e-10); norm += feat[f][b]; }
            norm /= bands;
            double len = 0;
            for (int b = 0; b < bands; b++) { feat[f][b] -= norm; len += feat[f][b] * feat[f][b]; }
            len = Math.sqrt(len);
            for (int b = 0; b < bands; b++) feat[f][b] /= Math.max(len, 1e-9);
        }
        int minLag = (int) Math.ceil(4.0 * sr / hop);
        int matched = 0;
        Map<Integer, Integer> lagVotes = new HashMap<>();
        for (int a = 0; a < frames; a++) {
            double best = 0;
            int bestLag = 0;
            for (int b = a + minLag; b < frames; b++) {
                double dot = 0;
                for (int k = 0; k < bands; k++) dot += feat[a][k] * feat[b][k];
                if (dot > best) { best = dot; bestLag = b - a; }
            }
            if (best > 0.995) {
                matched++;
                lagVotes.put(bestLag, (lagVotes.containsKey(bestLag) ? lagVotes.get(bestLag) : 0) + 1);
            }
        }
        int topLag = 0, topVotes = 0;
        for (Map.Entry<Integer, Integer> e : lagVotes.entrySet()) if (e.getValue() > topVotes) { topVotes = e.getValue(); topLag = e.getKey(); }
        double pct = 100.0 * matched / frames;
        put(r, "Near-identical repeated segments", String.format(Locale.ROOT, "%.1f%% of %.2f s windows recur ≥4 s later%s", pct, hop / (double) sr,
                topVotes > 0 ? String.format(Locale.ROOT, "; most common repeat distance %.1f s (%d windows)", topLag * hop / (double) sr, topVotes) : ""));
        r.fingerprint.put("signal.repetition", pct > 30 ? "high" : pct > 10 ? "moderate" : "low");
    }

    // ---- helpers ----

    private static boolean verifyEqual(short[] d, int a, int b, int len) {
        for (int i = 0; i < len; i++) if (d[a + i] != d[b + i]) return false;
        return true;
    }

    /** Open-addressing long→int map (no boxing in the per-sample loop). */
    static final class LongIntMap {
        private final long[] keys;
        private final int[] values;
        private final boolean[] used;
        private final int mask;

        LongIntMap(int expected) {
            int cap = Integer.highestOneBit(Math.max(4, expected * 2) - 1) << 1;
            keys = new long[cap];
            values = new int[cap];
            used = new boolean[cap];
            mask = cap - 1;
        }

        private int slot(long k) {
            long x = k * 0x9E3779B97F4A7C15L;
            int i = (int) (x ^ (x >>> 32)) & mask;
            while (used[i] && keys[i] != k) i = (i + 1) & mask;
            return i;
        }

        boolean containsKey(long k) { return used[slot(k)]; }
        void put(long k, int v) { int i = slot(k); used[i] = true; keys[i] = k; values[i] = v; }
        int get(long k) { int i = slot(k); return used[i] ? values[i] : -1; }
    }

    private static float[] mono(PcmAudio pcm) {
        if (pcm.channels.length == 1) return pcm.channels[0];
        float[] out = new float[pcm.frames];
        for (int i = 0; i < pcm.frames; i++) {
            float sum = 0;
            for (float[] c : pcm.channels) sum += c[i];
            out[i] = sum / pcm.channels.length;
        }
        return out;
    }

    private static final Map<Integer, float[]> WINDOWS = new HashMap<>();

    private static synchronized float[] hann(int n) {
        float[] w = WINDOWS.get(n);
        if (w == null) {
            w = new float[n];
            for (int i = 0; i < n; i++) w[i] = (float) (0.5 - 0.5 * Math.cos(2 * Math.PI * i / (n - 1)));
            WINDOWS.put(n, w);
        }
        return w;
    }

    /** In-place iterative radix-2 FFT. */
    static final class Fft {
        static void transform(double[] re, double[] im) {
            int n = re.length;
            for (int i = 1, j = 0; i < n; i++) {
                int bit = n >> 1;
                for (; (j & bit) != 0; bit >>= 1) j ^= bit;
                j ^= bit;
                if (i < j) {
                    double t = re[i]; re[i] = re[j]; re[j] = t;
                    t = im[i]; im[i] = im[j]; im[j] = t;
                }
            }
            for (int len = 2; len <= n; len <<= 1) {
                double ang = -2 * Math.PI / len;
                double wr = Math.cos(ang), wi = Math.sin(ang);
                for (int i = 0; i < n; i += len) {
                    double cr = 1, ci = 0;
                    for (int k = 0; k < len / 2; k++) {
                        int a = i + k, b = i + k + len / 2;
                        double xr = re[b] * cr - im[b] * ci, xi = re[b] * ci + im[b] * cr;
                        re[b] = re[a] - xr; im[b] = im[a] - xi;
                        re[a] += xr; im[a] += xi;
                        double nr = cr * wr - ci * wi;
                        ci = cr * wi + ci * wr;
                        cr = nr;
                    }
                }
            }
        }
    }
}
