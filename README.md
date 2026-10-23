# BareTrack

BareTrack is an Android audio player with a deliberate import-only library. It does not scan the device or populate itself from the media library.

## Import, clean, retag, export

1. Pick one or more MP3 or WAV files in the Android file picker.
2. BareTrack makes private app copies and immediately removes metadata. For MP3 this removes ID3v1/v2 tags, hidden/private frames, embedded artwork, APE/Lyrics3 tag data, recognized Xing/Info/VBRI encoder index frames, and bytes outside valid MPEG Layer III frames. For WAV this keeps only the validated format and audio data chunks, discarding other chunks such as INFO, bext, iXML, axml, cue, and embedded ID3.
3. Enter track metadata yourself, one track at a time or with shared batch tags.
4. Export the clean, retagged audio files to a folder you choose.
5. After export succeeds, choose whether to delete the exact source files selected for import. Providers that do not allow deletion leave the original in place and report that result.

The original is kept until the export has been written. Exported files use the title entered in BareTrack as their filename and keep the original extension. The source picker URI is kept in private app data only so BareTrack can offer deletion of that exact original after export; it is cleared when that original is deleted or the clean copy is removed. The stripped and edited copies stay in the app's private storage.

## WAV format support

BareTrack accepts standard RIFF/WAVE files with PCM, IEEE-float, or PCM/float WAVE_FORMAT_EXTENSIBLE audio. Compressed WAV codecs and RF64 files are not supported. Entered WAV metadata is written as a fresh ID3v2.4 chunk. WAV audio samples are copied unchanged; non-audio chunks are not retained.

## What “deep strip” means

The cleaners write new files from validated audio data. Tag containers and unknown metadata chunks are not copied. The app does not re-encode audio, so it preserves the MP3 frames or WAV samples byte-for-byte. Data deliberately encoded into the audio signal itself cannot be detected or guaranteed removed by a metadata tag stripper.

BareTrack writes standard ID3v2.4 fields plus arbitrary custom `TXXX` tags. It has no network permission and does not read other tracks unless the user selects them.

## Build

Open the project in Android Studio and build the `app` debug variant, or run:

```sh
gradle testDebugUnitTest assembleDebug
```

The GitHub Actions workflow runs the unit tests, builds the debug APK, and publishes it as the `BareTrack-debug-apk` workflow artifact.
