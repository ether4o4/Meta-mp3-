package com.whitetea.baretrack.playback;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.media.AudioAttributes;
import android.media.AudioManager;
import android.media.MediaPlayer;
import android.media.session.MediaSession;
import android.media.session.PlaybackState;
import android.os.Binder;
import android.os.Build;
import android.os.IBinder;
import android.os.PowerManager;

import com.whitetea.baretrack.MainActivity;
import com.whitetea.baretrack.R;
import com.whitetea.baretrack.model.Song;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

public final class PlaybackService extends Service {
    public interface Listener {
        void onPlaybackChanged(Song song, int positionMs, int durationMs, boolean playing, boolean preparing);
    }

    public static final String ACTION_INIT = "com.whitetea.baretrack.INIT";
    private static final String ACTION_PLAY = "com.whitetea.baretrack.PLAY";
    private static final String ACTION_PAUSE = "com.whitetea.baretrack.PAUSE";
    private static final String ACTION_NEXT = "com.whitetea.baretrack.NEXT";
    private static final String ACTION_PREVIOUS = "com.whitetea.baretrack.PREVIOUS";
    private static final String CHANNEL_ID = "baretrack_playback";
    private static final int NOTIFICATION_ID = 4107;

    private final IBinder binder = new LocalBinder();
    private final ArrayList<Song> queue = new ArrayList<>();
    private MediaPlayer player;
    private MediaSession mediaSession;
    private AudioManager audioManager;
    private AudioManager.OnAudioFocusChangeListener audioFocusListener;
    private Listener listener;
    private int index = -1;
    private boolean playing;
    private boolean preparing;
    private boolean foreground;

    public final class LocalBinder extends Binder {
        public PlaybackService getService() { return PlaybackService.this; }
    }

    @Override public void onCreate() {
        super.onCreate();
        audioManager = (AudioManager) getSystemService(AUDIO_SERVICE);
        audioFocusListener = change -> {
            if (change == AudioManager.AUDIOFOCUS_LOSS || change == AudioManager.AUDIOFOCUS_LOSS_TRANSIENT) pause();
            else if (change == AudioManager.AUDIOFOCUS_GAIN) {
                if (player != null) player.setVolume(1.0f, 1.0f);
                if (!playing && player != null && !preparing) resume();
            } else if (change == AudioManager.AUDIOFOCUS_LOSS_TRANSIENT_CAN_DUCK && player != null) {
                player.setVolume(0.25f, 0.25f);
            }
        };
        createNotificationChannel();
        mediaSession = new MediaSession(this, "BareTrack");
        mediaSession.setCallback(new MediaSession.Callback() {
            @Override public void onPlay() { resume(); }
            @Override public void onPause() { pause(); }
            @Override public void onSkipToNext() { next(); }
            @Override public void onSkipToPrevious() { previous(); }
            @Override public void onSeekTo(long pos) { seekTo((int) pos); }
        });
        mediaSession.setActive(true);
    }

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        ensureForeground();
        String action = intent == null ? ACTION_INIT : intent.getAction();
        if (ACTION_PLAY.equals(action)) resume();
        else if (ACTION_PAUSE.equals(action)) pause();
        else if (ACTION_NEXT.equals(action)) next();
        else if (ACTION_PREVIOUS.equals(action)) previous();
        return START_STICKY;
    }

    @Override public IBinder onBind(Intent intent) { return binder; }

    public void setListener(Listener listener) {
        this.listener = listener;
        publishState();
    }

    public void playQueue(List<Song> songs, int startIndex) {
        queue.clear();
        queue.addAll(songs);
        if (queue.isEmpty()) return;
        index = Math.max(0, Math.min(startIndex, queue.size() - 1));
        playCurrent();
    }

    public void replaceQueue(List<Song> songs) {
        String currentId = currentSong() == null ? null : currentSong().id();
        queue.clear();
        queue.addAll(songs);
        index = -1;
        if (currentId != null) {
            for (int i = 0; i < queue.size(); i++) {
                if (queue.get(i).id().equals(currentId)) { index = i; break; }
            }
        }
        if (index < 0 && player != null) stopPlayback();
        else {
            updateSession();
            updateNotification();
            publishState();
        }
    }

    public void toggle() {
        if (playing) pause();
        else if (player != null && !preparing) resume();
        else if (!queue.isEmpty() && index >= 0) playCurrent();
    }

    public void pause() {
        if (player != null && player.isPlaying()) {
            player.pause();
            playing = false;
            abandonAudioFocus();
            updateSession();
            updateNotification();
            publishState();
        }
    }

    public void resume() {
        if (player == null) {
            if (!queue.isEmpty() && index >= 0) playCurrent();
            return;
        }
        if (preparing || playing) return;
        if (!requestAudioFocus()) return;
        try {
            player.start();
            playing = true;
            updateSession();
            updateNotification();
            publishState();
        } catch (IllegalStateException ignored) { }
    }

    public void next() {
        if (queue.isEmpty()) return;
        index = (index + 1 + queue.size()) % queue.size();
        playCurrent();
    }

    public void previous() {
        if (queue.isEmpty()) return;
        if (player != null && safePosition() > 3000) {
            seekTo(0);
            return;
        }
        index = (index - 1 + queue.size()) % queue.size();
        playCurrent();
    }

    public void seekTo(int positionMs) {
        if (player == null || preparing) return;
        try { player.seekTo(Math.max(0, Math.min(positionMs, safeDuration()))); }
        catch (IllegalStateException ignored) { }
    }

    public Song currentSong() {
        return index >= 0 && index < queue.size() ? queue.get(index) : null;
    }

    public boolean isPlaying() { return playing; }
    public boolean isPreparing() { return preparing; }
    public int positionMs() { return safePosition(); }
    public int durationMs() { return safeDuration(); }

    private void playCurrent() {
        Song song = currentSong();
        if (song == null) return;
        releasePlayer();
        ensureForeground();
        preparing = true;
        playing = false;
        publishState();
        File file = new File(new File(getFilesDir(), "music"), song.fileName());
        try {
            player = new MediaPlayer();
            player.setAudioAttributes(new AudioAttributes.Builder()
                    .setUsage(AudioAttributes.USAGE_MEDIA)
                    .setContentType(AudioAttributes.CONTENT_TYPE_MUSIC)
                    .build());
            player.setWakeMode(this, PowerManager.PARTIAL_WAKE_LOCK);
            player.setDataSource(file.getAbsolutePath());
            player.setOnPreparedListener(mp -> {
                preparing = false;
                if (requestAudioFocus()) {
                    mp.start();
                    playing = true;
                }
                updateSession();
                updateNotification();
                publishState();
            });
            player.setOnCompletionListener(mp -> next());
            player.setOnErrorListener((mp, what, extra) -> {
                preparing = false;
                playing = false;
                publishState();
                return true;
            });
            player.prepareAsync();
            updateSession();
            updateNotification();
        } catch (Exception e) {
            preparing = false;
            playing = false;
            releasePlayer();
            publishState();
        }
    }

    private void stopPlayback() {
        releasePlayer();
        index = -1;
        playing = false;
        preparing = false;
        abandonAudioFocus();
        stopForeground(true);
        foreground = false;
        stopSelf();
        publishState();
    }

    private void releasePlayer() {
        if (player == null) return;
        try { player.setOnPreparedListener(null); } catch (Exception ignored) { }
        try { player.setOnCompletionListener(null); } catch (Exception ignored) { }
        try { player.reset(); } catch (Exception ignored) { }
        try { player.release(); } catch (Exception ignored) { }
        player = null;
    }

    private void ensureForeground() {
        if (foreground) return;
        startForeground(NOTIFICATION_ID, buildNotification());
        foreground = true;
    }

    private Notification buildNotification() {
        Song song = currentSong();
        String title = song == null ? "BareTrack" : song.displayTitle(index);
        String subtitle = song == null ? "Choose songs to play" : song.displayArtist();
        Notification.Builder builder = Build.VERSION.SDK_INT >= 26
                ? new Notification.Builder(this, CHANNEL_ID)
                : new Notification.Builder(this);
        builder.setSmallIcon(android.R.drawable.ic_media_play)
                .setContentTitle(title)
                .setContentText(subtitle)
                .setOnlyAlertOnce(true)
                .setOngoing(playing)
                .setContentIntent(activityIntent());
        builder.addAction(action(android.R.drawable.ic_media_previous, "Previous", ACTION_PREVIOUS));
        builder.addAction(action(playing ? android.R.drawable.ic_media_pause : android.R.drawable.ic_media_play,
                playing ? "Pause" : "Play", playing ? ACTION_PAUSE : ACTION_PLAY));
        builder.addAction(action(android.R.drawable.ic_media_next, "Next", ACTION_NEXT));
        if (Build.VERSION.SDK_INT >= 21) {
            Notification.MediaStyle style = new Notification.MediaStyle()
                    .setMediaSession(mediaSession.getSessionToken())
                    .setShowActionsInCompactView(0, 1, 2);
            builder.setStyle(style);
        }
        return builder.build();
    }

    private Notification.Action action(int icon, String label, String action) {
        Intent intent = new Intent(this, PlaybackService.class).setAction(action);
        PendingIntent pending = PendingIntent.getService(this, action.hashCode(), intent,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        return new Notification.Action.Builder(icon, label, pending).build();
    }

    private PendingIntent activityIntent() {
        Intent intent = new Intent(this, MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP);
        return PendingIntent.getActivity(this, 0, intent,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
    }

    private void updateNotification() {
        if (!foreground) return;
        NotificationManager manager = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        manager.notify(NOTIFICATION_ID, buildNotification());
    }

    private void updateSession() {
        if (mediaSession == null) return;
        Song song = currentSong();
        if (song != null) {
            mediaSession.setMetadata(new android.media.MediaMetadata.Builder()
                    .putString(android.media.MediaMetadata.METADATA_KEY_TITLE, song.displayTitle(index))
                    .putString(android.media.MediaMetadata.METADATA_KEY_ARTIST, song.displayArtist())
                    .putString(android.media.MediaMetadata.METADATA_KEY_ALBUM, song.tags().get("Album"))
                    .putLong(android.media.MediaMetadata.METADATA_KEY_DURATION, safeDuration())
                    .build());
        }
        long actions = PlaybackState.ACTION_PLAY | PlaybackState.ACTION_PAUSE | PlaybackState.ACTION_PLAY_PAUSE
                | PlaybackState.ACTION_SKIP_TO_NEXT | PlaybackState.ACTION_SKIP_TO_PREVIOUS | PlaybackState.ACTION_SEEK_TO;
        int state = playing ? PlaybackState.STATE_PLAYING : (preparing ? PlaybackState.STATE_BUFFERING : PlaybackState.STATE_PAUSED);
        mediaSession.setPlaybackState(new PlaybackState.Builder()
                .setActions(actions)
                .setState(state, safePosition(), playing ? 1.0f : 0.0f)
                .build());
    }

    private void publishState() {
        if (listener != null) listener.onPlaybackChanged(currentSong(), safePosition(), safeDuration(), playing, preparing);
    }

    private int safePosition() {
        try { return player == null || preparing ? 0 : Math.max(0, player.getCurrentPosition()); }
        catch (Exception ignored) { return 0; }
    }

    private int safeDuration() {
        try { return player == null || preparing ? 0 : Math.max(0, player.getDuration()); }
        catch (Exception ignored) { return 0; }
    }

    private boolean requestAudioFocus() {
        if (audioManager == null) return true;
        int result = audioManager.requestAudioFocus(audioFocusListener, AudioManager.STREAM_MUSIC, AudioManager.AUDIOFOCUS_GAIN);
        return result == AudioManager.AUDIOFOCUS_REQUEST_GRANTED;
    }

    private void abandonAudioFocus() {
        if (audioManager != null && audioFocusListener != null) audioManager.abandonAudioFocus(audioFocusListener);
    }

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT < 26) return;
        NotificationChannel channel = new NotificationChannel(CHANNEL_ID, "Music playback", NotificationManager.IMPORTANCE_LOW);
        channel.setDescription("Playback controls for BareTrack");
        ((NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE)).createNotificationChannel(channel);
    }

    @Override public void onDestroy() {
        releasePlayer();
        abandonAudioFocus();
        if (mediaSession != null) { mediaSession.setActive(false); mediaSession.release(); }
        super.onDestroy();
    }
}
