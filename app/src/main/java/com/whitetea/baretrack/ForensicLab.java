package com.whitetea.baretrack;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.Dialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.database.Cursor;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.provider.DocumentsContract;
import android.provider.OpenableColumns;
import android.text.InputType;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.HorizontalScrollView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import com.whitetea.baretrack.forensics.AndroidPcmDecoder;
import com.whitetea.baretrack.forensics.AudioForensics;
import com.whitetea.baretrack.forensics.Evidence;
import com.whitetea.baretrack.forensics.Fingerprint;
import com.whitetea.baretrack.forensics.ForensicReport;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.ExecutorService;

/**
 * The provenance lab: read-only forensic examination of any audio file, report viewing and export,
 * extraction of embedded payloads (C2PA manifests, artwork, hidden bytes) and reference fingerprints.
 * Examined files are copied into private cache, analysed, and the copy is deleted; originals are never written.
 */
final class ForensicLab {
    static final int REQUEST_INSPECT = 81;
    static final int REQUEST_SAVE_REPORT = 82;

    interface Host {
        void setStatus(String status);
        ExecutorService io();
    }

    private static final int INK = 0xFF1C2421;
    private static final int MUTED = 0xFF6E7771;
    private static final int PAPER = 0xFFF4F2ED;
    private static final int CARD = 0xFFFFFFFF;
    private static final int ACCENT = 0xFF315B50;
    private static final int LINE = 0xFFE2E4DE;

    private final Activity activity;
    private final Host host;
    private final Fingerprint.Store references;
    private byte[] pendingSave;

    ForensicLab(Activity activity, Host host) {
        this.activity = activity;
        this.host = host;
        this.references = new Fingerprint.Store(new File(activity.getFilesDir(), "reference-fingerprints"));
    }

    // ---------------- main-screen card ----------------

    View buildCard() {
        LinearLayout card = new LinearLayout(activity);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setBackground(round(CARD, LINE, dp(15)));
        card.setPadding(dp(17), dp(16), dp(17), dp(16));
        card.addView(label("Provenance lab", 18, INK, true));
        TextView copy = label("Examine any audio file read-only before you clean it: every tag, chunk and atom, hidden and "
                + "private data, C2PA content credentials with signature checks, encoder fingerprints and the audio signal. "
                + "The original is never modified.", 14, MUTED, false);
        LinearLayout.LayoutParams copyParams = params(-1, -2);
        copyParams.topMargin = dp(7);
        card.addView(copy, copyParams);
        LinearLayout row = new LinearLayout(activity);
        row.setOrientation(LinearLayout.HORIZONTAL);
        LinearLayout.LayoutParams rowParams = params(-1, -2);
        rowParams.topMargin = dp(14);
        card.addView(row, rowParams);
        row.addView(button("Inspect audio", true, v -> launchPicker()), new LinearLayout.LayoutParams(0, dp(48), 1));
        int count = references.list().size();
        Button refs = button(count == 0 ? "References" : "References (" + count + ")", false, v -> showReferences());
        LinearLayout.LayoutParams refParams = new LinearLayout.LayoutParams(0, dp(48), 1);
        refParams.leftMargin = dp(9);
        row.addView(refs, refParams);
        return card;
    }

    void launchPicker() {
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("*/*");
        intent.putExtra(Intent.EXTRA_MIME_TYPES, new String[] {"audio/*", "video/mp4", "application/ogg", "application/octet-stream"});
        intent.putExtra(Intent.EXTRA_ALLOW_MULTIPLE, true);
        intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        activity.startActivityForResult(intent, REQUEST_INSPECT);
    }

    boolean onActivityResult(int requestCode, int resultCode, Intent data) {
        if (requestCode != REQUEST_INSPECT && requestCode != REQUEST_SAVE_REPORT) return false;
        if (resultCode != Activity.RESULT_OK || data == null) { pendingSave = null; return true; }
        if (requestCode == REQUEST_INSPECT) {
            ArrayList<Uri> uris = new ArrayList<>();
            if (data.getClipData() != null) {
                for (int i = 0; i < data.getClipData().getItemCount(); i++) {
                    Uri u = data.getClipData().getItemAt(i).getUri();
                    if (u != null) uris.add(u);
                }
            } else if (data.getData() != null) uris.add(data.getData());
            if (!uris.isEmpty()) examine(uris);
        } else {
            writePending(data.getData());
        }
        return true;
    }

    // ---------------- examination ----------------

    /** Examine provider documents (originals in Files, or a track's persisted source). */
    void examine(List<Uri> uris) {
        host.setStatus("Working: examining " + uris.size() + (uris.size() == 1 ? " file…" : " files…"));
        final List<Fingerprint.Reference> refs = references.list();
        host.io().execute(() -> {
            final List<ForensicReport> reports = new ArrayList<>();
            final List<String> failures = new ArrayList<>();
            for (int i = 0; i < uris.size(); i++) {
                Uri uri = uris.get(i);
                File copy = new File(cacheDir(), "exam_" + UUID.randomUUID() + ".bin");
                try {
                    AudioForensics.Options options = new AudioForensics.Options();
                    describe(uri, options);
                    try (InputStream in = activity.getContentResolver().openInputStream(uri);
                         OutputStream out = new BufferedOutputStream(new FileOutputStream(copy))) {
                        if (in == null) throw new java.io.IOException("Could not read the selected file.");
                        byte[] buffer = new byte[64 * 1024];
                        int n;
                        while ((n = in.read(buffer)) != -1) out.write(buffer, 0, n);
                    }
                    options.decoder = new AndroidPcmDecoder();
                    options.references = refs;
                    final int index = i + 1;
                    reports.add(AudioForensics.examine(copy, options, stage -> activity.runOnUiThread(() ->
                            host.setStatus("Working: " + stage + " (" + index + "/" + uris.size() + ")…"))));
                } catch (Throwable e) {
                    failures.add(e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage());
                } finally {
                    //noinspection ResultOfMethodCallIgnored
                    copy.delete();
                }
            }
            activity.runOnUiThread(() -> finished(reports, failures));
        });
    }

    /** Examine a file BareTrack already holds (for example a clean copy, to confirm what the strip left). */
    void examineLocal(File file, String displayName) {
        host.setStatus("Working: examining " + displayName + "…");
        final List<Fingerprint.Reference> refs = references.list();
        host.io().execute(() -> {
            final List<ForensicReport> reports = new ArrayList<>();
            final List<String> failures = new ArrayList<>();
            try {
                AudioForensics.Options options = new AudioForensics.Options();
                options.providerName = displayName;
                options.decoder = new AndroidPcmDecoder();
                options.references = refs;
                reports.add(AudioForensics.examine(file, options, stage -> activity.runOnUiThread(() -> host.setStatus("Working: " + stage + "…"))));
            } catch (Throwable e) {
                failures.add(e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage());
            }
            activity.runOnUiThread(() -> finished(reports, failures));
        });
    }

    private void finished(List<ForensicReport> reports, List<String> failures) {
        String status = reports.size() + (reports.size() == 1 ? " file examined." : " files examined.");
        if (!failures.isEmpty()) status += " " + failures.size() + " failed: " + failures.get(0);
        host.setStatus(status);
        if (reports.size() == 1) showReport(reports.get(0));
        else if (reports.size() > 1) showSummary(reports);
    }

    private void describe(Uri uri, AudioForensics.Options o) {
        o.providerMime = activity.getContentResolver().getType(uri);
        try (Cursor c = activity.getContentResolver().query(uri, null, null, null, null)) {
            if (c != null && c.moveToFirst()) {
                int name = c.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                int size = c.getColumnIndex(OpenableColumns.SIZE);
                int modified = c.getColumnIndex(DocumentsContract.Document.COLUMN_LAST_MODIFIED);
                if (name >= 0 && !c.isNull(name)) o.providerName = c.getString(name);
                if (size >= 0 && !c.isNull(size)) o.providerSize = c.getLong(size);
                if (modified >= 0 && !c.isNull(modified)) o.providerModified = c.getLong(modified);
            }
        } catch (Exception ignored) { }
    }

    private File cacheDir() {
        File dir = new File(activity.getCacheDir(), "forensics");
        //noinspection ResultOfMethodCallIgnored
        dir.mkdirs();
        return dir;
    }

    // ---------------- report UI ----------------

    private void showSummary(List<ForensicReport> reports) {
        Dialog dialog = sheet();
        LinearLayout shell = shell(dialog, "Examined " + reports.size() + " files");
        LinearLayout list = new LinearLayout(activity);
        list.setOrientation(LinearLayout.VERTICAL);
        ScrollView scroll = new ScrollView(activity);
        scroll.addView(list);
        shell.addView(scroll, new LinearLayout.LayoutParams(-1, 0, 1));
        for (ForensicReport r : reports) {
            LinearLayout row = new LinearLayout(activity);
            row.setOrientation(LinearLayout.VERTICAL);
            row.setBackground(round(CARD, LINE, dp(12)));
            row.setPadding(dp(13), dp(11), dp(13), dp(11));
            row.addView(label(r.fileName, 15, INK, true));
            TextView v = label(r.verdict(), 12, tierColor(r.strongestTier()), false);
            row.addView(v);
            row.setOnClickListener(x -> showReport(r));
            LinearLayout.LayoutParams p = params(-1, -2);
            p.topMargin = dp(8);
            list.addView(row, p);
        }
        LinearLayout actions = actionRow(shell);
        actions.addView(button("Close", false, v -> dialog.dismiss()), new LinearLayout.LayoutParams(0, dp(46), 1));
        dialog.show();
    }

    void showReport(ForensicReport r) {
        Dialog dialog = sheet();
        LinearLayout shell = shell(dialog, r.fileName);

        LinearLayout verdict = new LinearLayout(activity);
        verdict.setOrientation(LinearLayout.HORIZONTAL);
        verdict.setBackground(round(CARD, LINE, dp(12)));
        verdict.setPadding(dp(12), dp(10), dp(12), dp(10));
        View stripe = new View(activity);
        stripe.setBackgroundColor(tierColor(r.strongestTier()));
        verdict.addView(stripe, new LinearLayout.LayoutParams(dp(4), -1));
        LinearLayout vText = new LinearLayout(activity);
        vText.setOrientation(LinearLayout.VERTICAL);
        LinearLayout.LayoutParams vtp = new LinearLayout.LayoutParams(0, -2, 1);
        vtp.leftMargin = dp(10);
        verdict.addView(vText, vtp);
        vText.addView(label(r.strongestTier() == Evidence.Tier.INFO ? "NO ATTRIBUTION EVIDENCE" : r.strongestTier().label.toUpperCase(Locale.ROOT), 11, MUTED, true));
        vText.addView(label(r.verdict(), 13, INK, false));
        vText.addView(label(r.container + (r.codec.isEmpty() ? "" : " · " + r.codec), 11, MUTED, false));
        LinearLayout.LayoutParams verdictParams = params(-1, -2);
        verdictParams.topMargin = dp(8);
        shell.addView(verdict, verdictParams);

        TextView body = new TextView(activity);
        body.setText(r.toText());
        body.setTextSize(11);
        body.setTextColor(INK);
        body.setTypeface(Typeface.MONOSPACE);
        body.setTextIsSelectable(true);
        body.setHorizontallyScrolling(false);
        body.setPadding(dp(4), dp(10), dp(4), dp(10));
        ScrollView scroll = new ScrollView(activity);
        scroll.addView(body);
        shell.addView(scroll, new LinearLayout.LayoutParams(-1, 0, 1));

        HorizontalScrollView barScroll = new HorizontalScrollView(activity);
        barScroll.setHorizontalScrollBarEnabled(false);
        LinearLayout bar = new LinearLayout(activity);
        bar.setOrientation(LinearLayout.HORIZONTAL);
        barScroll.addView(bar);
        LinearLayout.LayoutParams barParams = params(-1, -2);
        barParams.topMargin = dp(10);
        shell.addView(barScroll, barParams);
        chip(bar, "Export .txt", true, v -> save(r.toText().getBytes(StandardCharsets.UTF_8), "text/plain", base(r) + "_provenance.txt"));
        chip(bar, "Export .json", false, v -> save(r.toJson().getBytes(StandardCharsets.UTF_8), "application/json", base(r) + "_provenance.json"));
        chip(bar, "Copy", false, v -> copy(r.toText()));
        if (!r.blobs.isEmpty()) chip(bar, "Embedded data (" + r.blobs.size() + ")", false, v -> showBlobs(r));
        chip(bar, "Save as reference", false, v -> saveReference(r));
        chip(bar, "Suno verifier", false, v -> openVerifier(r));
        chip(bar, "Close", false, v -> dialog.dismiss());
        dialog.show();
    }

    private void showBlobs(ForensicReport r) {
        String[] items = new String[r.blobs.size()];
        for (int i = 0; i < items.length; i++) {
            ForensicReport.Blob b = r.blobs.get(i);
            items[i] = b.label + " — " + b.data.length + " bytes";
        }
        new AlertDialog.Builder(activity)
                .setTitle("Extract embedded data")
                .setItems(items, (d, which) -> {
                    ForensicReport.Blob b = r.blobs.get(which);
                    save(b.data, b.mime, base(r) + "_" + b.suggestedName);
                })
                .setNegativeButton("Close", null)
                .show();
    }

    private void openVerifier(ForensicReport r) {
        boolean hasManifest = false;
        for (ForensicReport.Blob b : r.blobs) if (b.mime.equals("application/c2pa")) hasManifest = true;
        String message = "Suno's verifier checks the credential against Suno's trust list, which this offline app cannot do. "
                + "Upload the original audio file there" + (hasManifest ? " (or the C2PA manifest from “Embedded data”)." : ".")
                + "\n\nIf it confirms the file, come back and use “Save as reference”: later files signed by the same certificate will then be reported as confirmed.";
        new AlertDialog.Builder(activity)
                .setTitle("Official verification")
                .setMessage(message)
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Open verifier", (d, w) -> {
                    try {
                        activity.startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(AudioForensics.SUNO_VERIFIER)));
                    } catch (Exception e) {
                        toast("No browser is available to open " + AudioForensics.SUNO_VERIFIER);
                    }
                })
                .show();
    }

    private void saveReference(ForensicReport r) {
        if (r.fingerprint.isEmpty()) { toast("This file has no fingerprint traits to save."); return; }
        EditText input = new EditText(activity);
        input.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_CAP_SENTENCES);
        input.setHint("e.g. Verified Suno download, my DAW export");
        input.setText(r.c2pa != null && r.c2pa.namesSuno() ? "Verified Suno download" : "");
        LinearLayout wrap = new LinearLayout(activity);
        wrap.setPadding(dp(20), dp(6), dp(20), 0);
        wrap.addView(input, params(-1, -2));
        new AlertDialog.Builder(activity)
                .setTitle("Save as reference profile")
                .setMessage("Only save files whose origin you have verified. New files are compared against this export fingerprint"
                        + (r.c2pa != null && !r.c2pa.signerSha256.isEmpty() ? ", and its C2PA signer certificate is pinned." : "."))
                .setView(wrap)
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Save", (d, w) -> {
                    String label = input.getText().toString().trim();
                    if (label.isEmpty()) label = r.fileName;
                    try {
                        references.save(label, r.fileName, r.fingerprint);
                        toast("Reference saved: " + label);
                        host.setStatus("Reference profile saved: " + label);
                    } catch (Exception e) {
                        toast("Could not save the reference: " + e.getMessage());
                    }
                })
                .show();
    }

    private void showReferences() {
        List<Fingerprint.Reference> list = references.list();
        if (list.isEmpty()) {
            new AlertDialog.Builder(activity)
                    .setTitle("Reference profiles")
                    .setMessage("None saved yet. Examine a file whose origin you have verified — for example a fresh Suno download "
                            + "confirmed by Suno's verifier, a Udio download, or your own DAW export — and choose “Save as reference”. "
                            + "Every later examination is compared against your references.")
                    .setPositiveButton("OK", null)
                    .show();
            return;
        }
        String[] items = new String[list.size()];
        DateFormat fmt = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT);
        for (int i = 0; i < items.length; i++) {
            Fingerprint.Reference ref = list.get(i);
            items[i] = ref.label + "\n" + ref.sourceFile + " · " + fmt.format(new Date(ref.savedAt)) + " · " + ref.fingerprint.features().size() + " traits";
        }
        new AlertDialog.Builder(activity)
                .setTitle("Reference profiles")
                .setItems(items, (d, which) -> confirmDeleteReference(list.get(which)))
                .setNegativeButton("Close", null)
                .show();
    }

    private void confirmDeleteReference(Fingerprint.Reference ref) {
        StringBuilder traits = new StringBuilder();
        for (java.util.Map.Entry<String, String> e : ref.fingerprint.features().entrySet()) {
            traits.append(e.getKey()).append(": ").append(e.getValue()).append('\n');
        }
        new AlertDialog.Builder(activity)
                .setTitle(ref.label)
                .setMessage(traits.toString().trim())
                .setNegativeButton("Keep", null)
                .setPositiveButton("Delete", (d, w) -> {
                    references.delete(ref.id);
                    host.setStatus("Reference removed: " + ref.label);
                })
                .show();
    }

    // ---------------- saving ----------------

    private void save(byte[] data, String mime, String name) {
        pendingSave = data;
        Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType(mime == null || mime.isEmpty() ? "application/octet-stream" : mime);
        intent.putExtra(Intent.EXTRA_TITLE, name.replaceAll("[\\\\/:*?\"<>|\\p{Cntrl}]", "_"));
        try {
            activity.startActivityForResult(intent, REQUEST_SAVE_REPORT);
        } catch (Exception e) {
            pendingSave = null;
            toast("No app is available to save files.");
        }
    }

    private void writePending(Uri target) {
        final byte[] data = pendingSave;
        pendingSave = null;
        if (target == null || data == null) return;
        host.io().execute(() -> {
            String result;
            try (OutputStream out = activity.getContentResolver().openOutputStream(target, "w")) {
                if (out == null) throw new java.io.IOException("The destination could not be opened.");
                out.write(data);
                result = "Saved " + data.length + " bytes.";
            } catch (Exception e) {
                result = "Could not save: " + (e.getMessage() == null ? "write failed" : e.getMessage());
            }
            final String message = result;
            activity.runOnUiThread(() -> toast(message));
        });
    }

    private void copy(String text) {
        ClipboardManager cm = (ClipboardManager) activity.getSystemService(Context.CLIPBOARD_SERVICE);
        if (cm != null) {
            cm.setPrimaryClip(ClipData.newPlainText("Provenance report", text));
            toast("Report copied.");
        }
    }

    private static String base(ForensicReport r) {
        String n = r.fileName;
        int dot = n.lastIndexOf('.');
        if (dot > 0) n = n.substring(0, dot);
        n = n.replaceAll("[^A-Za-z0-9 ._-]", "_").trim();
        return n.isEmpty() ? "audio" : n;
    }

    // ---------------- view helpers (BareTrack palette) ----------------

    private Dialog sheet() {
        Dialog dialog = new Dialog(activity);
        dialog.requestWindowFeature(Window.FEATURE_NO_TITLE);
        return dialog;
    }

    private LinearLayout shell(Dialog dialog, String title) {
        LinearLayout shell = new LinearLayout(activity);
        shell.setOrientation(LinearLayout.VERTICAL);
        shell.setBackgroundColor(PAPER);
        shell.setPadding(dp(16), dp(14), dp(16), dp(12));
        TextView brand = label("PROVENANCE EXAMINATION", 11, MUTED, true);
        brand.setLetterSpacing(0.12f);
        shell.addView(brand);
        TextView t = label(title, 18, INK, true);
        t.setMaxLines(2);
        shell.addView(t);
        dialog.setContentView(shell);
        Window w = dialog.getWindow();
        if (w != null) {
            w.setLayout(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT);
            w.setBackgroundDrawable(new android.graphics.drawable.ColorDrawable(PAPER));
            w.clearFlags(WindowManager.LayoutParams.FLAG_DIM_BEHIND);
        }
        return shell;
    }

    private LinearLayout actionRow(LinearLayout shell) {
        LinearLayout row = new LinearLayout(activity);
        row.setOrientation(LinearLayout.HORIZONTAL);
        LinearLayout.LayoutParams p = params(-1, -2);
        p.topMargin = dp(10);
        shell.addView(row, p);
        return row;
    }

    private void chip(LinearLayout bar, String text, boolean primary, View.OnClickListener click) {
        Button b = button(text, primary, click);
        LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(-2, dp(44));
        if (bar.getChildCount() > 0) p.leftMargin = dp(8);
        bar.addView(b, p);
    }

    private int tierColor(Evidence.Tier tier) {
        return tier == Evidence.Tier.CONFIRMED || tier == Evidence.Tier.PROBABLE ? ACCENT : tier == Evidence.Tier.SUPPORTING ? INK : MUTED;
    }

    private Button button(String text, boolean primary, View.OnClickListener click) {
        Button button = new Button(activity);
        button.setText(text);
        button.setTextSize(14);
        button.setAllCaps(false);
        button.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        button.setTextColor(primary ? 0xFFFFFFFF : INK);
        button.setBackground(round(primary ? ACCENT : CARD, primary ? ACCENT : LINE, dp(12)));
        button.setPadding(dp(14), 0, dp(14), 0);
        button.setMinHeight(dp(44));
        button.setGravity(Gravity.CENTER);
        button.setOnClickListener(click);
        return button;
    }

    private TextView label(String text, int size, int color, boolean bold) {
        TextView view = new TextView(activity);
        view.setText(text);
        view.setTextSize(size);
        view.setTextColor(color);
        if (bold) view.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        return view;
    }

    private GradientDrawable round(int color, int stroke, int radius) {
        GradientDrawable d = new GradientDrawable();
        d.setColor(color);
        d.setCornerRadius(radius);
        if (stroke != 0) d.setStroke(dp(1), stroke);
        return d;
    }

    private void toast(String text) { Toast.makeText(activity, text, Toast.LENGTH_LONG).show(); }
    private LinearLayout.LayoutParams params(int w, int h) { return new LinearLayout.LayoutParams(w, h); }
    private int dp(float v) { return (int) (v * activity.getResources().getDisplayMetrics().density + 0.5f); }
}
