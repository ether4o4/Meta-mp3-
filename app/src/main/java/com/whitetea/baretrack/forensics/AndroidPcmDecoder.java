package com.whitetea.baretrack.forensics;

import android.media.MediaCodec;
import android.media.MediaExtractor;
import android.media.MediaFormat;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/** Decodes compressed audio (MP3, AAC, FLAC, Vorbis, Opus…) to PCM with the platform codecs. */
public final class AndroidPcmDecoder implements PcmAudio.Provider {
    private static final long TIMEOUT_US = 10_000;

    @Override public PcmAudio decode(File file, int maxSeconds) throws IOException {
        MediaExtractor extractor = new MediaExtractor();
        MediaCodec codec = null;
        try {
            extractor.setDataSource(file.getAbsolutePath());
            int track = -1;
            MediaFormat format = null;
            for (int i = 0; i < extractor.getTrackCount(); i++) {
                MediaFormat f = extractor.getTrackFormat(i);
                String mime = f.getString(MediaFormat.KEY_MIME);
                if (mime != null && mime.startsWith("audio/")) { track = i; format = f; break; }
            }
            if (track < 0) return null;
            extractor.selectTrack(track);
            String mime = format.getString(MediaFormat.KEY_MIME);
            int rate = format.getInteger(MediaFormat.KEY_SAMPLE_RATE);
            int channels = format.getInteger(MediaFormat.KEY_CHANNEL_COUNT);
            codec = MediaCodec.createDecoderByType(mime);
            codec.configure(format, null, null, 0);
            codec.start();

            int keep = Math.min(2, Math.max(1, channels));
            long maxFrames = (long) rate * maxSeconds;
            float[][] out = new float[keep][(int) Math.min(maxFrames, 1 << 16)];
            int frames = 0;
            boolean inputDone = false, outputDone = false, truncated = false;
            MediaCodec.BufferInfo info = new MediaCodec.BufferInfo();
            int pcmEncoding = 2; // AudioFormat.ENCODING_PCM_16BIT
            int idleAfterInput = 0;
            while (!outputDone) {
                if (!inputDone) {
                    int in = codec.dequeueInputBuffer(TIMEOUT_US);
                    if (in >= 0) {
                        ByteBuffer buf = codec.getInputBuffer(in);
                        buf.clear();
                        int size = extractor.readSampleData(buf, 0);
                        if (size < 0) {
                            codec.queueInputBuffer(in, 0, 0, 0, MediaCodec.BUFFER_FLAG_END_OF_STREAM);
                            inputDone = true;
                        } else {
                            codec.queueInputBuffer(in, 0, size, extractor.getSampleTime(), 0);
                            extractor.advance();
                        }
                    }
                }
                int outIndex = codec.dequeueOutputBuffer(info, TIMEOUT_US);
                if (outIndex == MediaCodec.INFO_TRY_AGAIN_LATER && inputDone && ++idleAfterInput > 300) break;
                if (outIndex == MediaCodec.INFO_OUTPUT_FORMAT_CHANGED) {
                    MediaFormat f = codec.getOutputFormat();
                    if (f.containsKey(MediaFormat.KEY_SAMPLE_RATE)) rate = f.getInteger(MediaFormat.KEY_SAMPLE_RATE);
                    if (f.containsKey(MediaFormat.KEY_CHANNEL_COUNT)) channels = f.getInteger(MediaFormat.KEY_CHANNEL_COUNT);
                    if (f.containsKey("pcm-encoding")) pcmEncoding = f.getInteger("pcm-encoding");
                    keep = Math.min(2, Math.max(1, channels));
                    if (frames == 0) out = new float[keep][out[0].length];
                    maxFrames = (long) rate * maxSeconds;
                } else if (outIndex >= 0) {
                    ByteBuffer buf = codec.getOutputBuffer(outIndex);
                    buf.position(info.offset);
                    buf.limit(info.offset + info.size);
                    ByteBuffer data = buf.slice().order(ByteOrder.nativeOrder());
                    boolean isFloat = pcmEncoding == 4; // AudioFormat.ENCODING_PCM_FLOAT
                    int bytesPer = isFloat ? 4 : 2;
                    int count = info.size / (bytesPer * channels);
                    if (frames + count > maxFrames) { count = (int) (maxFrames - frames); truncated = true; }
                    if (count > 0) {
                        if (frames + count > out[0].length) {
                            int cap = (int) Math.min(maxFrames, Math.max(frames + count, out[0].length * 2L));
                            float[][] grown = new float[keep][cap];
                            for (int c = 0; c < keep; c++) System.arraycopy(out[c], 0, grown[c], 0, frames);
                            out = grown;
                        }
                        for (int i = 0; i < count; i++) {
                            for (int c = 0; c < channels; c++) {
                                float v = isFloat ? data.getFloat() : data.getShort() / 32768f;
                                if (c < keep && keep <= out.length) out[c][frames + i] = v;
                            }
                        }
                        frames += count;
                    }
                    codec.releaseOutputBuffer(outIndex, false);
                    if ((info.flags & MediaCodec.BUFFER_FLAG_END_OF_STREAM) != 0 || truncated) outputDone = true;
                }
            }
            if (frames == 0) return null;
            float[][] trimmed = new float[keep][frames];
            for (int c = 0; c < keep; c++) System.arraycopy(out[c], 0, trimmed[c], 0, frames);
            return new PcmAudio(trimmed, rate, frames, "Android MediaCodec " + mime + " decoder (decoded, not bit-exact)", 0, 0, truncated);
        } catch (RuntimeException e) {
            throw new IOException("Platform decoder failed: " + e.getMessage(), e);
        } finally {
            if (codec != null) {
                try { codec.stop(); } catch (RuntimeException ignored) { }
                codec.release();
            }
            extractor.release();
        }
    }
}
