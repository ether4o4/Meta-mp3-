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

## Provenance lab (read-only forensic examination)

**Inspect audio** on the main screen examines any audio file without changing it. BareTrack copies the file into private cache, examines the copy, then deletes the copy. You can also open a track's menu and choose **Inspect original** (the source file in Files, before stripping) or **Inspect clean copy** (to check what the strip left behind).

The examination has seven parts:

1. **Container dissection.** Every ID3v2 frame, padding region, MPEG frame run, gap and trailing byte. Every RIFF/RF64/AIFF chunk, MP4 atom, FLAC metadata block and Ogg page and logical stream, with byte offsets.
2. **Complete metadata extraction.** ID3v2.2/2.3/2.4, including compressed and unsynchronised frames, TXXX, COMM/USLT, SYLT, PRIV, GEOB, UFID and APIC. Also ID3v1/1.1/TAG+, APEv1/v2, Lyrics3 v1/v2, RIFF LIST INFO, BWF bext (originator, UMID, loudness, coding history), iXML, aXML, XMP, embedded WAV/AIFF ID3, iTunes/QuickTime ilst (including `----` freeform and `keys`), MP4 creation and modification timestamps, Vorbis comments and Opus tags. Cover art is checked for dimensions, EXIF (with thumbnails), XMP, PNG text chunks (including image-generator `parameters`/`prompt`), ICC profiles and a SHA-256 you can match against known artwork. Every value is searched for UUIDs/GUIDs, hash-length hex strings, URLs, JSON, Base64 payloads (which are decoded and searched again) and invisible Unicode. A raw-byte scan in ASCII, UTF-16LE and UTF-16BE looks for generator and tool identifiers (Suno, Udio and others, `com.suno.fingerprint`, IPTC `trainedAlgorithmicMedia`, C2PA/JUMBF, LAME, FFmpeg, DAWs) and reports which structure holds each hit.
3. **C2PA verification.** The tool finds manifest stores in ID3 GEOB frames, RIFF `C2PA` chunks, MP4 `uuid` boxes, FLAC APPLICATION blocks, cover art (JPEG APP11, PNG caBX) and unreferenced bytes. It decodes the active claim and assertions (actions, digitalSourceType, soft bindings) and checks three things offline: the COSE_Sign1 claim signature (ES256/384/512, PS256/384/512, Ed25519 where the device supports it), every hashed-assertion reference, and the `c2pa.hash.data` content binding against the file's bytes. The signer certificate chain is decoded and its links are checked.
4. **Encoder identification.** The Xing/Info and LAME/FFmpeg encoder tag: version string, VBR method, low-pass, encoder delay/padding, preset, ReplayGain, music length and tag CRC. Also VBRI, the bitrate and channel-mode distributions, header bits, bit-reservoir use, chunk and atom order, FLAC/Vorbis vendor strings, MP4 handler and ©too. The tool cross-checks the index frame count against the real stream, LAME's music length against the actual bytes, and the tag encoder against the stream encoder.
5. **Audio signal examination.** WAV/AIFF are read sample-exact; other formats are decoded with the platform codecs. Measured: level, crest factor, DC offset, clipping, effective bit depth (it catches 16-bit audio padded into 24-bit files), and the spectral centroid, roll-off and band energy. It finds the high-frequency cutoff, cross-checks it against the encoder low-pass, and flags lossless files with lossy-style band limits. It also measures L/R and per-band correlation, inter-channel phase, onset rate, bit-exact repeated audio at any alignment, near-identical repeated segments, and stationary narrowband tones in the high band.
6. **Cross-platform fingerprint comparison.** Each file gets an export fingerprint built from traits that survive retagging. **Save as reference** stores the fingerprint of a file whose origin you verified, such as a fresh Suno download that Suno's verifier confirmed, a Udio download, or your own DAW export. Later files are scored against your references. A saved reference also pins its C2PA signer certificate. No profiles ship with the app, so the app never asserts a fingerprint you did not verify.
7. **Evidence report.** Findings are ranked as Confirmed, Probable, Supporting, Inconclusive or Observation, and the report ends with a verdict and the limits of the examination. You can export it as text or JSON, or copy it. The C2PA manifest, artwork and unreferenced byte regions can each be extracted to a file.

**Hashes.** The report gives SHA-256, SHA-1 and MD5 of the file. It also gives an audio-payload SHA-256 that ignores tags. For MP3 this equals the hash of a BareTrack clean export, so you can tie a stripped copy back to its original. For FLAC the report also shows the stream's decoded-audio MD5.

**What it will not claim.** A credential is reported as *Confirmed* only if three things hold: the signature verifies, the content binding matches, and the signer certificate equals one you pinned from a verified reference. BareTrack has no network permission, so it cannot check the C2PA/Suno trust lists or revocation. Use [Suno's verifier](https://suno.com/suno-credentials) for that. Missing credentials prove nothing, because only newer downloads carry them. String matches are leads, not attribution. Signal measurements describe the sound and do not detect AI generation, and proprietary watermarks are not decoded.

## Build

Open the project in Android Studio and build the `app` debug variant, or run:

```sh
gradle testDebugUnitTest assembleDebug
```

The GitHub Actions workflow runs the unit tests, builds the debug APK, and publishes it as the `BareTrack-debug-apk` workflow artifact.
