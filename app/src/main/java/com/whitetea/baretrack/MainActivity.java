package com.whitetea.baretrack;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.Dialog;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.content.pm.PackageManager;
import android.content.res.ColorStateList;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.provider.DocumentsContract;
import android.text.InputType;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.PopupMenu;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.SeekBar;
import android.widget.TextView;
import android.widget.Toast;

import com.whitetea.baretrack.audio.Id3TagWriter;
import com.whitetea.baretrack.audio.Mp3Sanitizer;
import com.whitetea.baretrack.audio.WavSanitizer;
import com.whitetea.baretrack.audio.WavTagWriter;
import com.whitetea.baretrack.data.SongStore;
import com.whitetea.baretrack.model.Song;
import com.whitetea.baretrack.model.SongTags;
import com.whitetea.baretrack.playback.PlaybackService;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class MainActivity extends Activity {
    private static final int REQUEST_IMPORT = 71;
    private static final int REQUEST_EXPORT_FOLDER = 72;
    private static final int REQUEST_NOTIFICATIONS = 73;

    private static final int INK = 0xFF1C2421;
    private static final int MUTED = 0xFF6E7771;
    private static final int PAPER = 0xFFF4F2ED;
    private static final int CARD = 0xFFFFFFFF;
    private static final int ACCENT = 0xFF315B50;
    private static final int LINE = 0xFFE2E4DE;

    private SongStore store;
    private File musicDir;
    private final ExecutorService io = Executors.newSingleThreadExecutor();
    private final Handler mainHandler = new Handler(Looper.getMainLooper());
    private final LinkedHashSet<String> selected = new LinkedHashSet<>();
    private ArrayList<Song> songs = new ArrayList<>();
    private ArrayList<String> pendingExportIds = new ArrayList<>();
    private ArrayList<Song> pendingQueue;
    private int pendingPlayIndex;
    private PlaybackService playback;
    private boolean bound;
    private boolean batchMode;
    private boolean trackingSeek;
    private String status = "Choose the MP3 or WAV files you want to clean.";
    private LinearLayout root;
    private LinearLayout libraryBox;
    private LinearLayout batchBox;
    private TextView countLabel;
    private TextView statusLabel;
    private TextView nowTitle;
    private TextView nowArtist;
    private TextView playButton;
    private TextView timeLabel;
    private SeekBar seekBar;
    private Song playingSong;
    private boolean isPlaying;
    private boolean isPreparing;
    private int durationMs;
    private int positionMs;

    private final PlaybackService.Listener playbackListener = (song, position, duration, playing, preparing) -> {
        playingSong = song;
        positionMs = position;
        durationMs = duration;
        isPlaying = playing;
        isPreparing = preparing;
        renderPlayer();
    };

    private final Runnable playerTicker = new Runnable() {
        @Override public void run() {
            if (playback != null) {
                positionMs = playback.positionMs();
                durationMs = playback.durationMs();
                renderPlayer();
            }
            mainHandler.postDelayed(this, 500);
        }
    };

    private final ServiceConnection serviceConnection = new ServiceConnection() {
        @Override public void onServiceConnected(ComponentName name, IBinder service) {
            playback = ((PlaybackService.LocalBinder) service).getService();
            playback.setListener(playbackListener);
            if (pendingQueue != null) {
                playback.playQueue(pendingQueue, pendingPlayIndex);
                pendingQueue = null;
            }
            playback.replaceQueue(store.all());
        }

        @Override public void onServiceDisconnected(ComponentName name) { playback = null; }
    };

    @Override protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().setStatusBarColor(INK);
        getWindow().setNavigationBarColor(INK);
        getWindow().getDecorView().setSystemUiVisibility(0);
        store = new SongStore(this);
        musicDir = new File(getFilesDir(), "music");
        musicDir.mkdirs();
        bound = bindService(new Intent(this, PlaybackService.class), serviceConnection, Context.BIND_AUTO_CREATE);
        refreshSongs();
        buildScreen();
    }

    @Override protected void onDestroy() {
        mainHandler.removeCallbacks(playerTicker);
        if (playback != null) playback.setListener(null);
        if (bound) unbindService(serviceConnection);
        io.shutdown();
        super.onDestroy();
    }

    @Override protected void onResume() {
        super.onResume();
        mainHandler.removeCallbacks(playerTicker);
        mainHandler.post(playerTicker);
    }

    @Override protected void onPause() {
        mainHandler.removeCallbacks(playerTicker);
        super.onPause();
    }

    @Override protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (resultCode != RESULT_OK || data == null) return;
        if (requestCode == REQUEST_IMPORT) handleImportResult(data);
        else if (requestCode == REQUEST_EXPORT_FOLDER) handleExportFolder(data);
    }

    private void refreshSongs() {
        songs = store.all();
        for (int i = songs.size() - 1; i >= 0; i--) {
            if (!new File(musicDir, songs.get(i).fileName()).isFile()) songs.remove(i);
        }
        if (playback != null) playback.replaceQueue(songs);
    }

    private void buildScreen() {
        root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(PAPER);

        LinearLayout top = new LinearLayout(this);
        top.setOrientation(LinearLayout.VERTICAL);
        top.setPadding(dp(22), dp(18), dp(22), dp(14));
        top.setBackgroundColor(INK);
        TextView brand = label("BARETRACK", 13, 0xFFC3D1C8, true);
        brand.setLetterSpacing(0.16f);
        top.addView(brand);
        TextView headline = label("Your files. Your tags.", 25, 0xFFF7F5EF, true);
        LinearLayout.LayoutParams headParams = params(-1, -2);
        headParams.topMargin = dp(8);
        top.addView(headline, headParams);
        TextView subtitle = label("Import only what you choose. Clean it, retag it, export it.", 14, 0xFFC4CBC5, false);
        LinearLayout.LayoutParams subParams = params(-1, -2);
        subParams.topMargin = dp(5);
        top.addView(subtitle, subParams);
        root.addView(top, params(-1, -2));

        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        LinearLayout content = new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        content.setPadding(dp(18), dp(18), dp(18), dp(20));
        scroll.addView(content);
        root.addView(scroll, new LinearLayout.LayoutParams(-1, 0, 1));

        LinearLayout importCard = card();
        importCard.setOrientation(LinearLayout.VERTICAL);
        importCard.setPadding(dp(17), dp(16), dp(17), dp(16));
        content.addView(importCard, params(-1, -2));
        TextView importTitle = label("Private import", 18, INK, true);
        importCard.addView(importTitle);
        TextView importCopy = label("Nothing is scanned from your phone. Pick MP3s or WAVs, and BareTrack strips their embedded metadata as they come in.", 14, MUTED, false);
        LinearLayout.LayoutParams copyParams = params(-1, -2);
        copyParams.topMargin = dp(7);
        importCard.addView(importCopy, copyParams);
        LinearLayout buttons = new LinearLayout(this);
        buttons.setOrientation(LinearLayout.HORIZONTAL);
        LinearLayout.LayoutParams buttonRow = params(-1, -2);
        buttonRow.topMargin = dp(14);
        importCard.addView(buttons, buttonRow);
        Button importButton = actionButton("Import audio", true, v -> launchImport());
        buttons.addView(importButton, new LinearLayout.LayoutParams(0, dp(48), 1));
        Button batchButton = actionButton(batchMode ? "Done" : "Batch tools", false,
                v -> { batchMode = !batchMode; selected.clear(); buildScreen(); });
        LinearLayout.LayoutParams batchButtonParams = new LinearLayout.LayoutParams(0, dp(48), 1);
        batchButtonParams.leftMargin = dp(9);
        buttons.addView(batchButton, batchButtonParams);

        LinearLayout statusCard = card();
        statusCard.setOrientation(LinearLayout.HORIZONTAL);
        statusCard.setGravity(Gravity.CENTER_VERTICAL);
        statusCard.setPadding(dp(14), dp(12), dp(14), dp(12));
        LinearLayout.LayoutParams statusParams = params(-1, -2);
        statusParams.topMargin = dp(12);
        content.addView(statusCard, statusParams);
        ProgressBar marker = new ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal);
        marker.setIndeterminate(true);
        marker.setVisibility(status.startsWith("Working") ? View.VISIBLE : View.GONE);
        marker.setProgressTintList(ColorStateList.valueOf(ACCENT));
        statusCard.addView(marker, new LinearLayout.LayoutParams(dp(22), dp(3)));
        statusLabel = label(status, 13, MUTED, false);
        LinearLayout.LayoutParams statusTextParams = new LinearLayout.LayoutParams(0, -2, 1);
        statusTextParams.leftMargin = dp(10);
        statusCard.addView(statusLabel, statusTextParams);

        LinearLayout heading = new LinearLayout(this);
        heading.setOrientation(LinearLayout.HORIZONTAL);
        heading.setGravity(Gravity.CENTER_VERTICAL);
        LinearLayout.LayoutParams headingParams = params(-1, -2);
        headingParams.topMargin = dp(22);
        content.addView(heading, headingParams);
        TextView libraryTitle = label("Your clean library", 19, INK, true);
        heading.addView(libraryTitle, new LinearLayout.LayoutParams(0, -2, 1));
        countLabel = label(songs.size() + (songs.size() == 1 ? " track" : " tracks"), 13, MUTED, false);
        heading.addView(countLabel);

        libraryBox = new LinearLayout(this);
        libraryBox.setOrientation(LinearLayout.VERTICAL);
        LinearLayout.LayoutParams listParams = params(-1, -2);
        listParams.topMargin = dp(10);
        content.addView(libraryBox, listParams);
        buildLibraryRows();

        batchBox = new LinearLayout(this);
        batchBox.setOrientation(LinearLayout.VERTICAL);
        LinearLayout.LayoutParams batchParams = params(-1, -2);
        batchParams.topMargin = dp(10);
        content.addView(batchBox, batchParams);
        buildBatchActions();

        LinearLayout privacy = card();
        privacy.setOrientation(LinearLayout.VERTICAL);
        privacy.setPadding(dp(15), dp(13), dp(15), dp(13));
        LinearLayout.LayoutParams privacyParams = params(-1, -2);
        privacyParams.topMargin = dp(16);
        content.addView(privacy, privacyParams);
        privacy.addView(label("What the deep strip removes", 14, INK, true));
        TextView privacyText = label("For MP3: ID3 tags (including hidden/private frames and cover art), APE, Lyrics3, encoder index frames, and bytes outside valid audio frames. For PCM/IEEE-float WAV: every non-audio chunk is removed, including INFO, broadcast metadata, XML, and embedded ID3. Audio samples are retained. Compressed WAV codecs and RF64 are not supported. The original stays in Files until you export and confirm deletion.", 12, MUTED, false);
        LinearLayout.LayoutParams privacyTextParams = params(-1, -2);
        privacyTextParams.topMargin = dp(6);
        privacy.addView(privacyText, privacyTextParams);

        root.addView(buildPlayerDock(), params(-1, -2));
        setContentView(root);
        renderPlayer();
    }

    private void buildLibraryRows() {
        libraryBox.removeAllViews();
        if (songs.isEmpty()) {
            LinearLayout empty = card();
            empty.setOrientation(LinearLayout.VERTICAL);
            empty.setGravity(Gravity.CENTER_HORIZONTAL);
            empty.setPadding(dp(22), dp(28), dp(22), dp(28));
            TextView title = label("No imported tracks yet", 17, INK, true);
            title.setGravity(Gravity.CENTER);
            empty.addView(title);
            TextView copy = label("Your library only contains songs you add here.", 13, MUTED, false);
            copy.setGravity(Gravity.CENTER);
            LinearLayout.LayoutParams copyParams = params(-1, -2);
            copyParams.topMargin = dp(6);
            empty.addView(copy, copyParams);
            libraryBox.addView(empty);
            return;
        }
        for (int i = 0; i < songs.size(); i++) {
            Song song = songs.get(i);
            final int position = i;
            LinearLayout row = card();
            row.setOrientation(LinearLayout.HORIZONTAL);
            row.setGravity(Gravity.CENTER_VERTICAL);
            row.setPadding(dp(10), dp(10), dp(9), dp(10));
            LinearLayout.LayoutParams rowParams = params(-1, -2);
            if (i > 0) rowParams.topMargin = dp(8);
            libraryBox.addView(row, rowParams);
            if (batchMode) {
                CheckBox check = new CheckBox(this);
                check.setButtonTintList(new ColorStateList(
                        new int[][] { new int[] { android.R.attr.state_checked }, new int[] {} },
                        new int[] { ACCENT, 0xFF929B94 }));
                check.setChecked(selected.contains(song.id()));
                check.setOnCheckedChangeListener((button, checked) -> {
                    if (checked) selected.add(song.id()); else selected.remove(song.id());
                    buildBatchActions();
                });
                row.addView(check, params(dp(42), dp(44)));
            } else {
                TextView play = label(playingSong != null && playingSong.id().equals(song.id()) && isPlaying ? "Ⅱ" : "▶", 15, ACCENT, true);
                play.setGravity(Gravity.CENTER);
                row.addView(play, params(dp(38), dp(42)));
            }
            LinearLayout textColumn = new LinearLayout(this);
            textColumn.setOrientation(LinearLayout.VERTICAL);
            textColumn.setPadding(dp(4), 0, dp(4), 0);
            row.addView(textColumn, new LinearLayout.LayoutParams(0, -2, 1));
            textColumn.addView(label(song.displayTitle(i), 15, INK, true));
            TextView artist = label(song.displayArtist(), 12, MUTED, false);
            LinearLayout.LayoutParams artistParams = params(-1, -2);
            artistParams.topMargin = dp(3);
            textColumn.addView(artist, artistParams);
            TextView menu = label("⋮", 23, MUTED, true);
            menu.setGravity(Gravity.CENTER);
            row.addView(menu, params(dp(40), dp(42)));
            menu.setOnClickListener(v -> showTrackMenu(menu, song));
            row.setOnClickListener(v -> {
                if (batchMode) {
                    if (selected.contains(song.id())) selected.remove(song.id()); else selected.add(song.id());
                    buildScreen();
                } else startPlayback(position);
            });
            row.setOnLongClickListener(v -> {
                batchMode = true;
                selected.add(song.id());
                buildScreen();
                return true;
            });
        }
    }

    private void buildBatchActions() {
        if (batchBox == null) return;
        batchBox.removeAllViews();
        if (!batchMode) return;
        LinearLayout panel = card();
        panel.setOrientation(LinearLayout.VERTICAL);
        panel.setPadding(dp(14), dp(14), dp(14), dp(14));
        batchBox.addView(panel);
        panel.addView(label(selected.size() + " selected", 15, INK, true));
        TextView explain = label("Choose several tracks, apply shared tags, then export them together.", 12, MUTED, false);
        LinearLayout.LayoutParams explainParams = params(-1, -2);
        explainParams.topMargin = dp(4);
        panel.addView(explain, explainParams);
        LinearLayout actions = new LinearLayout(this);
        actions.setOrientation(LinearLayout.HORIZONTAL);
        LinearLayout.LayoutParams actionParams = params(-1, -2);
        actionParams.topMargin = dp(11);
        panel.addView(actions, actionParams);
        Button selectAll = actionButton("Select all", false, v -> {
            if (selected.size() == songs.size()) selected.clear(); else for (Song s : songs) selected.add(s.id());
            buildScreen();
        });
        actions.addView(selectAll, new LinearLayout.LayoutParams(0, dp(44), 1));
        Button batchEdit = actionButton("Edit tags", false, v -> showBatchEditor());
        LinearLayout.LayoutParams editParams = new LinearLayout.LayoutParams(0, dp(44), 1);
        editParams.leftMargin = dp(8);
        actions.addView(batchEdit, editParams);
        Button export = actionButton("Export batch", true, v -> chooseExportFolder());
        LinearLayout.LayoutParams exportParams = params(-1, dp(46));
        exportParams.topMargin = dp(8);
        panel.addView(export, exportParams);
    }

    private View buildPlayerDock() {
        LinearLayout dock = new LinearLayout(this);
        dock.setOrientation(LinearLayout.VERTICAL);
        dock.setPadding(dp(18), dp(12), dp(18), dp(13));
        dock.setBackgroundColor(CARD);
        View divider = new View(this);
        divider.setBackgroundColor(LINE);
        dock.addView(divider, params(-1, dp(1)));
        LinearLayout labels = new LinearLayout(this);
        labels.setOrientation(LinearLayout.VERTICAL);
        LinearLayout.LayoutParams labelParams = params(-1, -2);
        labelParams.topMargin = dp(9);
        dock.addView(labels, labelParams);
        nowTitle = label("Nothing playing", 15, INK, true);
        labels.addView(nowTitle);
        nowArtist = label("Import tracks to start", 12, MUTED, false);
        labels.addView(nowArtist);
        seekBar = new SeekBar(this);
        seekBar.setMax(1000);
        seekBar.setProgressTintList(ColorStateList.valueOf(ACCENT));
        seekBar.setThumbTintList(ColorStateList.valueOf(ACCENT));
        LinearLayout.LayoutParams seekParams = params(-1, dp(28));
        seekParams.topMargin = dp(3);
        dock.addView(seekBar, seekParams);
        seekBar.setOnSeekBarChangeListener(new SeekBar.OnSeekBarChangeListener() {
            @Override public void onProgressChanged(SeekBar bar, int progress, boolean fromUser) {
                if (fromUser && durationMs > 0 && playback != null) playback.seekTo((int) (durationMs * (progress / 1000f)));
            }
            @Override public void onStartTrackingTouch(SeekBar bar) { trackingSeek = true; }
            @Override public void onStopTrackingTouch(SeekBar bar) { trackingSeek = false; }
        });
        LinearLayout controls = new LinearLayout(this);
        controls.setGravity(Gravity.CENTER);
        dock.addView(controls, params(-1, dp(39)));
        TextView previous = controlText("|◀");
        controls.addView(previous, params(dp(58), dp(38)));
        previous.setOnClickListener(v -> { if (playback != null) playback.previous(); });
        playButton = controlText("▶");
        playButton.setTextSize(20);
        playButton.setTextColor(ACCENT);
        controls.addView(playButton, params(dp(64), dp(38)));
        playButton.setOnClickListener(v -> {
            if (playback != null) playback.toggle();
            else if (!songs.isEmpty()) startPlayback(0);
        });
        TextView next = controlText("▶|");
        controls.addView(next, params(dp(58), dp(38)));
        next.setOnClickListener(v -> { if (playback != null) playback.next(); });
        timeLabel = label("0:00 / 0:00", 11, MUTED, false);
        timeLabel.setGravity(Gravity.CENTER);
        dock.addView(timeLabel, params(-1, dp(18)));
        return dock;
    }

    private void renderPlayer() {
        if (nowTitle == null || isFinishing()) return;
        if (playingSong == null) {
            nowTitle.setText("Nothing playing");
            nowArtist.setText("Import tracks to start");
        } else {
            int idx = 0;
            for (int i = 0; i < songs.size(); i++) if (songs.get(i).id().equals(playingSong.id())) { idx = i; break; }
            nowTitle.setText(playingSong.displayTitle(idx));
            nowArtist.setText(playingSong.displayArtist());
        }
        if (playButton != null) playButton.setText(isPlaying ? "Ⅱ" : (isPreparing ? "…" : "▶"));
        if (seekBar != null && !trackingSeek) {
            seekBar.setProgress(durationMs <= 0 ? 0 : (int) (positionMs * 1000f / durationMs));
        }
        if (timeLabel != null) timeLabel.setText(clock(positionMs) + " / " + clock(durationMs));
    }

    private void launchImport() {
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("audio/*");
        intent.putExtra(Intent.EXTRA_MIME_TYPES, new String[] {
                "audio/mpeg", "audio/mp3", "audio/x-mp3", "audio/wav", "audio/x-wav", "audio/wave", "audio/vnd.wave"
        });
        intent.putExtra(Intent.EXTRA_ALLOW_MULTIPLE, true);
        intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION |
                Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION);
        startActivityForResult(intent, REQUEST_IMPORT);
    }

    private void handleImportResult(Intent data) {
        ArrayList<Uri> uris = new ArrayList<>();
        if (data.getClipData() != null) {
            for (int i = 0; i < data.getClipData().getItemCount(); i++) {
                Uri uri = data.getClipData().getItemAt(i).getUri();
                if (uri != null) uris.add(uri);
            }
        } else if (data.getData() != null) uris.add(data.getData());
        if (uris.isEmpty()) return;
        setStatus("Working: stripping " + uris.size() + (uris.size() == 1 ? " file…" : " files…"));
        io.execute(() -> {
            ArrayList<String> importedIds = new ArrayList<>();
            ArrayList<String> failures = new ArrayList<>();
            for (Uri uri : uris) {
                String id = UUID.randomUUID().toString().replace("-", "");
                File input = new File(musicDir, "in_" + id + ".tmp");
                File raw = new File(musicDir, "raw_" + id + ".tmp");
                File output = null;
                try {
                    try (InputStream in = getContentResolver().openInputStream(uri);
                         OutputStream out = new BufferedOutputStream(new FileOutputStream(input))) {
                        if (in == null) throw new java.io.IOException("Could not read the selected file.");
                        byte[] buffer = new byte[64 * 1024];
                        int count;
                        while ((count = in.read(buffer)) != -1) out.write(buffer, 0, count);
                    }
                    String extension;
                    if (WavSanitizer.isWave(input)) {
                        extension = "wav";
                        WavSanitizer.strip(input, raw);
                    } else {
                        extension = "mp3";
                        Mp3Sanitizer.strip(input, raw);
                    }
                    output = new File(musicDir, id + "." + extension);
                    if (!raw.renameTo(output)) copyFile(raw, output);
                    if (!output.isFile() || output.length() == 0) throw new java.io.IOException("Clean audio output was not created.");
                    String source = persistSource(uri, dataFlagsForUri(data, uri));
                    store.add(new Song(id, SongTags.blank(), source, extension));
                    importedIds.add(id);
                } catch (Exception e) {
                    failures.add(e.getMessage() == null ? "Could not import a selected file." : e.getMessage());
                    if (output != null) output.delete();
                } finally {
                    input.delete();
                    raw.delete();
                }
            }
            runOnUiThread(() -> {
                refreshSongs();
                selected.clear();
                selected.addAll(importedIds);
                batchMode = !importedIds.isEmpty();
                String result = importedIds.size() + (importedIds.size() == 1 ? " audio file imported and stripped." : " audio files imported and stripped.");
                if (!failures.isEmpty()) result += " " + failures.size() + " file(s) skipped: " + failures.get(0);
                status = result;
                buildScreen();
                if (!importedIds.isEmpty()) toast("Select Edit tags or Export batch to finish this batch.");
            });
        });
    }

    private int dataFlagsForUri(Intent data, Uri uri) {
        return data.getFlags() & (Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION);
    }

    private String persistSource(Uri uri, int flags) {
        try {
            int persistFlags = flags & (Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION);
            if (persistFlags != 0) getContentResolver().takePersistableUriPermission(uri, persistFlags);
        } catch (Exception ignored) { }
        return uri.toString();
    }

    private void showTrackMenu(View anchor, Song song) {
        PopupMenu menu = new PopupMenu(this, anchor);
        menu.getMenu().add("Edit tags").setOnMenuItemClickListener(item -> { showEditor(song); return true; });
        menu.getMenu().add("Remove clean copy").setOnMenuItemClickListener(item -> {
            confirmRemove(song);
            return true;
        });
        menu.show();
    }

    private void confirmRemove(Song song) {
        new AlertDialog.Builder(this)
                .setTitle("Remove this clean copy?")
                .setMessage("This deletes the copy inside BareTrack. The original file in Files will stay where it is.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Remove copy", (d, w) -> {
                    new File(musicDir, song.fileName()).delete();
                    store.remove(song.id());
                    releaseSourcePermissionIfUnused(song.sourceUri());
                    selected.remove(song.id());
                    refreshSongs();
                    buildScreen();
                }).show();
    }

    private void showEditor(Song song) {
        SongTags tags = song.tags();
        Dialog dialog = new Dialog(this);
        dialog.requestWindowFeature(Window.FEATURE_NO_TITLE);
        LinearLayout shell = new LinearLayout(this);
        shell.setOrientation(LinearLayout.VERTICAL);
        shell.setBackgroundColor(PAPER);
        shell.setPadding(dp(18), dp(16), dp(18), dp(14));
        TextView title = label("Set the tags", 20, INK, true);
        shell.addView(title);
        TextView description = label("Only these values will be written into the clean " + (song.isWave() ? "WAV." : "MP3."), 13, MUTED, false);
        LinearLayout.LayoutParams descParams = params(-1, -2);
        descParams.topMargin = dp(4);
        shell.addView(description, descParams);
        ScrollView scroll = new ScrollView(this);
        LinearLayout fields = new LinearLayout(this);
        fields.setOrientation(LinearLayout.VERTICAL);
        scroll.addView(fields);
        LinearLayout.LayoutParams scrollParams = new LinearLayout.LayoutParams(-1, 0, 1);
        scrollParams.topMargin = dp(10);
        shell.addView(scroll, scrollParams);
        java.util.LinkedHashMap<String, EditText> edits = new java.util.LinkedHashMap<>();
        for (String field : SongTags.FIELDS) edits.put(field, addEditorField(fields, field, tags.get(field), false));
        StringBuilder custom = new StringBuilder();
        for (String key : tags.custom().keySet()) {
            if (custom.length() > 0) custom.append('\n');
            custom.append(key).append('=').append(tags.custom().get(key));
        }
        EditText customEdit = addEditorField(fields, "Custom tags (one key=value per line)", custom.toString(), true);
        LinearLayout buttons = new LinearLayout(this);
        buttons.setOrientation(LinearLayout.HORIZONTAL);
        LinearLayout.LayoutParams buttonsParams = params(-1, -2);
        buttonsParams.topMargin = dp(12);
        shell.addView(buttons, buttonsParams);
        Button cancel = actionButton("Cancel", false, v -> dialog.dismiss());
        buttons.addView(cancel, new LinearLayout.LayoutParams(0, dp(48), 1));
        Button save = actionButton("Save tags", true, v -> {
            SongTags changed = new SongTags();
            for (String key : edits.keySet()) changed.set(key, edits.get(key).getText().toString());
            parseCustom(customEdit.getText().toString(), changed, true);
            dialog.dismiss();
            writeTags(song, changed);
        });
        LinearLayout.LayoutParams saveParams = new LinearLayout.LayoutParams(0, dp(48), 1);
        saveParams.leftMargin = dp(8);
        buttons.addView(save, saveParams);
        dialog.setContentView(shell);
        Window window = dialog.getWindow();
        if (window != null) {
            window.setBackgroundDrawableResource(android.R.color.transparent);
            window.setLayout(getResources().getDisplayMetrics().widthPixels - dp(28), (int) (getResources().getDisplayMetrics().heightPixels * 0.88f));
        }
        dialog.show();
        if (dialog.getWindow() != null) dialog.getWindow().setLayout(getResources().getDisplayMetrics().widthPixels - dp(28), (int) (getResources().getDisplayMetrics().heightPixels * 0.88f));
    }

    private void showBatchEditor() {
        ArrayList<Song> targets = selectedSongs();
        if (targets.isEmpty()) { toast("Select at least one track first."); return; }
        Dialog dialog = new Dialog(this);
        dialog.requestWindowFeature(Window.FEATURE_NO_TITLE);
        LinearLayout shell = new LinearLayout(this);
        shell.setOrientation(LinearLayout.VERTICAL);
        shell.setBackgroundColor(PAPER);
        shell.setPadding(dp(18), dp(16), dp(18), dp(14));
        shell.addView(label("Shared batch tags", 20, INK, true));
        TextView note = label("Non-empty fields are applied to all " + targets.size() + " selected tracks. Blank fields stay unchanged.", 13, MUTED, false);
        LinearLayout.LayoutParams noteParams = params(-1, -2);
        noteParams.topMargin = dp(4);
        shell.addView(note, noteParams);
        ScrollView scroll = new ScrollView(this);
        LinearLayout fields = new LinearLayout(this);
        fields.setOrientation(LinearLayout.VERTICAL);
        scroll.addView(fields);
        LinearLayout.LayoutParams scrollParams = new LinearLayout.LayoutParams(-1, 0, 1);
        scrollParams.topMargin = dp(9);
        shell.addView(scroll, scrollParams);
        String[] batchFields = SongTags.FIELDS;
        java.util.LinkedHashMap<String, EditText> edits = new java.util.LinkedHashMap<>();
        for (String field : batchFields) edits.put(field, addEditorField(fields, field, "", field.equals("Lyrics")));
        EditText custom = addEditorField(fields, "Custom tags (one key=value per line)", "", true);
        LinearLayout actions = new LinearLayout(this);
        actions.setOrientation(LinearLayout.HORIZONTAL);
        LinearLayout.LayoutParams actionParams = params(-1, -2);
        actionParams.topMargin = dp(12);
        shell.addView(actions, actionParams);
        actions.addView(actionButton("Cancel", false, v -> dialog.dismiss()), new LinearLayout.LayoutParams(0, dp(48), 1));
        Button apply = actionButton("Apply to batch", true, v -> {
            ArrayList<Song> changed = new ArrayList<>();
            for (Song song : targets) {
                SongTags next = copyTags(song.tags());
                for (String field : edits.keySet()) {
                    String value = edits.get(field).getText().toString().trim();
                    if (!value.isEmpty()) next.set(field, value);
                }
                parseCustom(custom.getText().toString(), next, false);
                changed.add(new Song(song.id(), next, song.sourceUri(), song.extension()));
            }
            dialog.dismiss();
            writeBatchTags(changed);
        });
        LinearLayout.LayoutParams applyParams = new LinearLayout.LayoutParams(0, dp(48), 1);
        applyParams.leftMargin = dp(8);
        actions.addView(apply, applyParams);
        dialog.setContentView(shell);
        dialog.show();
        if (dialog.getWindow() != null) {
            dialog.getWindow().setBackgroundDrawableResource(android.R.color.transparent);
            dialog.getWindow().setLayout(getResources().getDisplayMetrics().widthPixels - dp(28), (int) (getResources().getDisplayMetrics().heightPixels * 0.88f));
        }
    }

    private EditText addEditorField(LinearLayout parent, String label, String value, boolean multiline) {
        TextView title = label(label, 12, MUTED, true);
        LinearLayout.LayoutParams titleParams = params(-1, -2);
        titleParams.topMargin = dp(10);
        parent.addView(title, titleParams);
        EditText edit = new EditText(this);
        edit.setText(value);
        edit.setTextColor(INK);
        edit.setTextSize(15);
        edit.setSingleLine(!multiline);
        edit.setMinHeight(dp(multiline ? 76 : 46));
        edit.setPadding(dp(11), dp(7), dp(11), dp(7));
        edit.setBackground(roundRect(CARD, LINE, dp(11)));
        edit.setInputType(multiline ? InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_MULTI_LINE | InputType.TYPE_TEXT_FLAG_CAP_SENTENCES
                : InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_CAP_SENTENCES);
        LinearLayout.LayoutParams editParams = params(-1, -2);
        editParams.topMargin = dp(4);
        parent.addView(edit, editParams);
        return edit;
    }

    private void parseCustom(String text, SongTags tags, boolean replace) {
        if (replace) {
            // A fresh SongTags is passed for individual edits, so no stale keys remain.
        }
        String[] lines = text.split("\\r?\\n");
        int count = 0;
        for (String line : lines) {
            int equals = line.indexOf('=');
            if (equals <= 0 || count >= 50) continue;
            tags.setCustom(line.substring(0, equals), line.substring(equals + 1));
            count++;
        }
    }

    private SongTags copyTags(SongTags original) {
        SongTags copy = new SongTags();
        for (String key : original.values().keySet()) copy.set(key, original.get(key));
        for (String key : original.custom().keySet()) copy.setCustom(key, original.custom().get(key));
        return copy;
    }

    private void sanitizeAndTag(Song song, File source, File raw, File target, SongTags tags) throws java.io.IOException {
        if (song.isWave()) {
            WavSanitizer.strip(source, raw);
            WavTagWriter.write(raw, target, tags);
        } else {
            Mp3Sanitizer.strip(source, raw);
            Id3TagWriter.write(raw, target, tags);
        }
    }

    private void writeTags(Song song, SongTags tags) {
        setStatus("Working: saving tags…");
        io.execute(() -> {
            try {
                File source = new File(musicDir, song.fileName());
                File raw = new File(musicDir, "retag_raw_" + song.id() + ".tmp");
                File target = new File(musicDir, "retag_" + song.id() + ".tmp");
                sanitizeAndTag(song, source, raw, target, tags);
                replaceFile(target, source);
                raw.delete();
                Song changed = new Song(song.id(), tags, song.sourceUri(), song.extension());
                store.update(changed);
                runOnUiThread(() -> { refreshSongs(); status = "Tags saved. The source file has not been changed."; buildScreen(); });
            } catch (Exception e) {
                new File(musicDir, "retag_raw_" + song.id() + ".tmp").delete();
                new File(musicDir, "retag_" + song.id() + ".tmp").delete();
                runOnUiThread(() -> { setStatus("Could not save tags: " + safeError(e)); });
            }
        });
    }

    private void writeBatchTags(ArrayList<Song> changedSongs) {
        setStatus("Working: saving tags for " + changedSongs.size() + " tracks…");
        io.execute(() -> {
            int saved = 0;
            for (Song changed : changedSongs) {
                File source = new File(musicDir, changed.fileName());
                File raw = new File(musicDir, "batch_raw_" + changed.id() + ".tmp");
                File target = new File(musicDir, "batch_" + changed.id() + ".tmp");
                try {
                    sanitizeAndTag(changed, source, raw, target, changed.tags());
                    replaceFile(target, source);
                    store.update(changed);
                    saved++;
                } catch (Exception ignored) { }
                raw.delete();
                target.delete();
            }
            int done = saved;
            runOnUiThread(() -> { refreshSongs(); status = "Tags saved on " + done + " of " + changedSongs.size() + " selected tracks."; buildScreen(); });
        });
    }

    private void chooseExportFolder() {
        ArrayList<Song> targets = selectedSongs();
        if (targets.isEmpty()) { toast("Select at least one track to export."); return; }
        pendingExportIds.clear();
        for (Song song : targets) pendingExportIds.add(song.id());
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT_TREE);
        intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION |
                Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION);
        startActivityForResult(intent, REQUEST_EXPORT_FOLDER);
    }

    private void handleExportFolder(Intent data) {
        Uri treeUri = data.getData();
        if (treeUri == null) return;
        try {
            int flags = data.getFlags() & (Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION);
            if (flags != 0) getContentResolver().takePersistableUriPermission(treeUri, flags);
        } catch (Exception ignored) { }
        ArrayList<Song> targets = new ArrayList<>();
        for (String id : pendingExportIds) {
            for (Song song : songs) if (song.id().equals(id)) { targets.add(song); break; }
        }
        setStatus("Working: exporting " + targets.size() + " clean audio files…");
        io.execute(() -> {
            ArrayList<String> successful = new ArrayList<>();
            ArrayList<String> failed = new ArrayList<>();
            HashSet<String> names = new HashSet<>();
            try {
                String treeId = DocumentsContract.getTreeDocumentId(treeUri);
                Uri directory = DocumentsContract.buildDocumentUriUsingTree(treeUri, treeId);
                int order = 1;
                for (Song song : targets) {
                    try {
                        File source = new File(musicDir, song.fileName());
                        String name = exportName(song, order++, names);
                        Uri destination = DocumentsContract.createDocument(getContentResolver(), directory, song.mimeType(), name);
                        if (destination == null) throw new java.io.IOException("The selected folder would not create an audio file.");
                        try (InputStream in = new BufferedInputStream(new FileInputStream(source));
                             OutputStream out = getContentResolver().openOutputStream(destination, "w")) {
                            if (out == null) throw new java.io.IOException("Could not write the audio file into the selected folder.");
                            byte[] buffer = new byte[64 * 1024];
                            int count;
                            while ((count = in.read(buffer)) != -1) out.write(buffer, 0, count);
                        }
                        successful.add(song.id());
                    } catch (Exception e) {
                        failed.add(song.displayTitle(order - 1) + ": " + safeError(e));
                    }
                }
            } catch (Exception e) {
                failed.add(safeError(e));
            }
            runOnUiThread(() -> afterExport(successful, failed));
        });
    }

    private String exportName(Song song, int order, Set<String> names) {
        String title = song.tags().get("Title");
        if (title.isEmpty()) title = String.format(Locale.US, "Untitled track %02d", order);
        title = title.replaceAll("[\\\\/:*?\"<>|\\p{Cntrl}]", "_").trim();
        while (title.endsWith(".")) title = title.substring(0, title.length() - 1).trim();
        if (title.isEmpty()) title = String.format(Locale.US, "Untitled track %02d", order);
        String base = title;
        int suffix = 2;
        String extension = song.extension();
        while (!names.add((title + "." + extension).toLowerCase(Locale.ROOT))) title = base + " (" + suffix++ + ")";
        return title + "." + extension;
    }

    private void afterExport(ArrayList<String> successful, ArrayList<String> failed) {
        refreshSongs();
        status = successful.size() + (successful.size() == 1 ? " clean audio file exported." : " clean audio files exported.");
        if (!failed.isEmpty()) status += " " + failed.size() + " could not export.";
        buildScreen();
        if (successful.isEmpty()) {
            toast("Nothing was exported successfully.");
            return;
        }
        boolean anySources = false;
        for (String id : successful) for (Song song : songs) if (song.id().equals(id) && !song.sourceUri().isEmpty()) anySources = true;
        if (!anySources) {
            new AlertDialog.Builder(this).setTitle("Export complete")
                    .setMessage(status + " No source files are linked for deletion.")
                    .setPositiveButton("Done", null).show();
            return;
        }
        String message = status + "\n\nDelete the original files you imported? BareTrack will only request deletion for those exact selections.";
        new AlertDialog.Builder(this).setTitle("Export complete")
                .setMessage(message)
                .setNegativeButton("Keep originals", null)
                .setPositiveButton("Delete originals", (dialog, which) -> deleteSources(successful))
                .show();
    }

    private void deleteSources(ArrayList<String> exportedIds) {
        setStatus("Working: removing selected originals…");
        io.execute(() -> {
            int deleted = 0;
            int failed = 0;
            Set<String> processedUris = new HashSet<>();
            ArrayList<Song> all = store.all();
            for (String id : exportedIds) {
                Song target = null;
                for (Song song : all) if (song.id().equals(id)) { target = song; break; }
                if (target == null || target.sourceUri().isEmpty()) continue;
                String source = target.sourceUri();
                if (!processedUris.add(source)) continue;
                boolean success = false;
                try { success = DocumentsContract.deleteDocument(getContentResolver(), Uri.parse(source)); }
                catch (Exception ignored) { }
                if (success) {
                    deleted++;
                    releaseSourcePermission(source);
                    for (Song song : all) if (song.sourceUri().equals(source)) store.update(new Song(song.id(), song.tags(), "", song.extension()));
                } else failed++;
            }
            int removed = deleted;
            int notRemoved = failed;
            runOnUiThread(() -> {
                refreshSongs();
                status = removed + " original file(s) deleted." + (notRemoved > 0 ? " " + notRemoved + " could not be deleted by the selected file provider." : "");
                buildScreen();
                new AlertDialog.Builder(this).setTitle("Source cleanup finished")
                        .setMessage(status + (notRemoved > 0 ? " Open Files and remove any remaining originals manually." : ""))
                        .setPositiveButton("Done", null).show();
            });
        });
    }

    private ArrayList<Song> selectedSongs() {
        ArrayList<Song> result = new ArrayList<>();
        for (Song song : songs) if (selected.contains(song.id())) result.add(song);
        return result;
    }

    private void releaseSourcePermission(String source) {
        if (source == null || source.isEmpty()) return;
        try {
            getContentResolver().releasePersistableUriPermission(Uri.parse(source),
                    Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION);
        } catch (Exception ignored) { }
    }

    private void releaseSourcePermissionIfUnused(String source) {
        if (source == null || source.isEmpty()) return;
        for (Song remaining : store.all()) if (source.equals(remaining.sourceUri())) return;
        releaseSourcePermission(source);
    }

    private void startPlayback(int position) {
        if (songs.isEmpty()) return;
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission("android.permission.POST_NOTIFICATIONS") != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[] { "android.permission.POST_NOTIFICATIONS" }, REQUEST_NOTIFICATIONS);
        }
        Intent service = new Intent(this, PlaybackService.class).setAction(PlaybackService.ACTION_INIT);
        if (Build.VERSION.SDK_INT >= 26) startForegroundService(service); else startService(service);
        if (playback != null) playback.playQueue(songs, position);
        else { pendingQueue = new ArrayList<>(songs); pendingPlayIndex = position; }
    }

    private void setStatus(String value) {
        status = value;
        if (statusLabel != null) statusLabel.setText(value);
        if (statusLabel != null) buildScreen();
    }

    private void copyFile(File source, File destination) throws java.io.IOException {
        try (InputStream in = new BufferedInputStream(new FileInputStream(source));
             OutputStream out = new BufferedOutputStream(new FileOutputStream(destination))) {
            byte[] buffer = new byte[64 * 1024];
            int count;
            while ((count = in.read(buffer)) != -1) out.write(buffer, 0, count);
        }
        source.delete();
    }

    private void replaceFile(File replacement, File original) throws java.io.IOException {
        File backup = new File(original.getParentFile(), original.getName() + ".bak");
        if (backup.exists()) backup.delete();
        if (!original.renameTo(backup)) throw new java.io.IOException("Could not safely replace the clean audio file.");
        if (!replacement.renameTo(original)) {
            backup.renameTo(original);
            throw new java.io.IOException("Could not safely install the new tags.");
        }
        backup.delete();
    }

    private void toast(String text) { Toast.makeText(this, text, Toast.LENGTH_LONG).show(); }

    private String safeError(Exception e) {
        String message = e.getMessage();
        return message == null || message.trim().isEmpty() ? "operation failed" : message;
    }

    private String clock(int millis) {
        int seconds = Math.max(0, millis / 1000);
        return String.format(Locale.US, "%d:%02d", seconds / 60, seconds % 60);
    }

    private LinearLayout card() {
        LinearLayout box = new LinearLayout(this);
        box.setBackground(roundRect(CARD, LINE, dp(15)));
        return box;
    }

    private GradientDrawable roundRect(int color, int stroke, int radius) {
        GradientDrawable drawable = new GradientDrawable();
        drawable.setColor(color);
        drawable.setCornerRadius(radius);
        if (stroke != 0) drawable.setStroke(dp(1), stroke);
        return drawable;
    }

    private TextView label(String text, int size, int color, boolean bold) {
        TextView view = new TextView(this);
        view.setText(text);
        view.setTextSize(size);
        view.setTextColor(color);
        if (bold) view.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        view.setIncludeFontPadding(true);
        return view;
    }

    private TextView controlText(String text) {
        TextView view = label(text, 16, INK, true);
        view.setGravity(Gravity.CENTER);
        return view;
    }

    private Button actionButton(String text, boolean primary, View.OnClickListener click) {
        Button button = new Button(this);
        button.setText(text);
        button.setTextSize(14);
        button.setAllCaps(false);
        button.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        button.setTextColor(primary ? 0xFFFFFFFF : INK);
        button.setBackground(roundRect(primary ? ACCENT : CARD, primary ? ACCENT : LINE, dp(12)));
        button.setPadding(dp(10), 0, dp(10), 0);
        button.setMinHeight(dp(44));
        button.setOnClickListener(click);
        return button;
    }

    private LinearLayout.LayoutParams params(int width, int height) { return new LinearLayout.LayoutParams(width, height); }
    private int dp(float value) { return (int) (value * getResources().getDisplayMetrics().density + 0.5f); }
}
