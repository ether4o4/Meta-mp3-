package com.whitetea.baretrack.forensics;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import com.whitetea.baretrack.audio.Mp3Sanitizer;

import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public final class AudioForensicsTest {

    // ---------------- C2PA ----------------

    @Test public void signedC2paWavVerifiesSignatureAssertionsAndBinding() throws Exception {
        File wav = fixture("c2pa_signed.wav");
        ForensicReport r = AudioForensics.examine(wav, new AudioForensics.Options(), null);
        assertNotNull("manifest store should be found in the RIFF C2PA chunk", r.c2pa);
        assertEquals(Boolean.TRUE, r.c2pa.signatureValid);
        assertEquals(Boolean.TRUE, r.c2pa.assertionHashesValid);
        assertEquals(Boolean.TRUE, r.c2pa.bindingValid);
        assertTrue(r.c2pa.claimGenerator.contains("Suno"));
        assertTrue(r.c2pa.aiDeclared());
        assertEquals("ES256", r.c2pa.signatureAlg);
        assertTrue(r.c2pa.chainConsistent);
        assertEquals(Evidence.Tier.PROBABLE, r.strongestTier());
        assertTrue(hasEvidence(r, Evidence.Tier.PROBABLE, "Cryptographically intact C2PA credential naming Suno"));
        assertTrue(r.verdict().contains("Cryptographically intact"));
        boolean manifestBlob = false;
        for (ForensicReport.Blob b : r.blobs) if (b.mime.equals("application/c2pa")) manifestBlob = true;
        assertTrue("manifest should be offered for extraction", manifestBlob);
    }

    @Test public void changingOneAudioSampleBreaksTheContentBindingButNotTheSignature() throws Exception {
        byte[] bytes = readAll(fixture("c2pa_signed.wav"));
        int data = indexOf(bytes, "data") + 8;
        bytes[data + 100] ^= 0x01;
        File tampered = temp("tampered.wav", bytes);
        ForensicReport r = AudioForensics.examine(tampered, new AudioForensics.Options(), null);
        assertEquals(Boolean.TRUE, r.c2pa.signatureValid);
        assertEquals(Boolean.FALSE, r.c2pa.bindingValid);
        assertTrue(hasEvidence(r, Evidence.Tier.PROBABLE, "audio changed after signing"));
    }

    @Test public void pinnedSignerFromAVerifiedReferenceIsReportedAsConfirmed() throws Exception {
        File wav = fixture("c2pa_signed.wav");
        ForensicReport first = AudioForensics.examine(wav, new AudioForensics.Options(), null);
        File dir = Files.createTempDirectory("refs").toFile();
        Fingerprint.Store store = new Fingerprint.Store(dir);
        store.save("Verified Suno download", "fixture.wav", first.fingerprint);
        AudioForensics.Options o = new AudioForensics.Options();
        o.references = store.list();
        ForensicReport second = AudioForensics.examine(wav, o, null);
        assertEquals(Evidence.Tier.CONFIRMED, second.strongestTier());
        assertTrue(second.verdict().startsWith("CONFIRMED"));
        assertFalse(second.fields(ForensicReport.SECTION_COMPARE).isEmpty());
    }

    @Test public void ecdsaRawSignaturesAreConvertedAndVerified() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(256);
        KeyPair kp = g.generateKeyPair();
        byte[] protectedHeader = {(byte) 0xA1, 0x01, 0x26};
        byte[] payload = "claim".getBytes(StandardCharsets.UTF_8);
        byte[] tbs = Cbor.encodeSigStructure("Signature1", protectedHeader, new byte[0], payload);
        Object decoded = Cbor.decode(tbs);
        assertTrue(decoded instanceof List);
        assertEquals("Signature1", ((List<?>) decoded).get(0));
        Signature s = Signature.getInstance("SHA256withECDSA");
        s.initSign(kp.getPrivate());
        s.update(tbs);
        byte[] raw = derToRaw(s.sign(), 32);
        assertTrue(C2paInspector.verify(-7, kp.getPublic(), tbs, raw));
        raw[5] ^= 1;
        assertFalse(C2paInspector.verify(-7, kp.getPublic(), tbs, raw));
    }

    // ---------------- MP3 ----------------

    @Test public void mp3HiddenDataTagsAndPayloadHashMatchTheCleanExport() throws Exception {
        List<byte[]> frames = new ArrayList<>();
        Random rnd = new Random(7);
        for (int i = 0; i < 8; i++) frames.add(mpegFrame(rnd));
        ByteArrayOutputStream f = new ByteArrayOutputStream();
        f.write(id3v23());
        for (int i = 0; i < frames.size(); i++) {
            f.write(frames.get(i));
            if (i == 3) f.write("HIDDEN-PAYLOAD 6f1c2a9e-3b4d-4e5f-8a9b-0c1d2e3f4a5b".getBytes(StandardCharsets.US_ASCII));
        }
        f.write(apeTag());
        f.write(id3v1("Night Drive"));
        File mp3 = temp("probe.mp3", f.toByteArray());

        ForensicReport r = AudioForensics.examine(mp3, new AudioForensics.Options(), null);
        assertEquals("MPEG audio with ID3v2", r.container);
        assertTrue(r.codec.startsWith("MPEG-1 Layer III"));
        assertTrue(hasField(r, "PRIV owner", "com.suno.app"));
        assertTrue(hasField(r, "TXXX [generator]", "Example Generator 2"));
        assertTrue(hasField(r, "Title", "Night Drive"));
        assertTrue(hasField(r, "ARTIST", "APE Artist"));
        assertTrue(hasEvidence(r, Evidence.Tier.PROBABLE, "com.suno"));
        assertTrue(hasEvidence(r, Evidence.Tier.SUPPORTING, "Bytes between audio frames"));
        assertTrue(hasEvidence(r, Evidence.Tier.SUPPORTING, "Non-zero bytes in ID3v2 padding"));
        assertTrue(hasField(r, "", "6f1c2a9e-3b4d-4e5f-8a9b-0c1d2e3f4a5b"));
        assertEquals("CBR 128", r.fingerprint.get("mpeg.bitrateMode"));

        File clean = new File(mp3.getParentFile(), "clean.mp3");
        Mp3Sanitizer.strip(mp3, clean);
        assertEquals("payload hash must survive the BareTrack strip", sha256(readAll(clean)), r.audioPayloadSha256);
        ForensicReport after = AudioForensics.examine(clean, new AudioForensics.Options(), null);
        assertEquals(r.audioPayloadSha256, after.audioPayloadSha256);
        assertFalse("the clean export should carry no generator markers", hasEvidence(after, Evidence.Tier.PROBABLE, "com.suno"));
        assertTrue(after.toJson().startsWith("{") && after.toJson().endsWith("}"));
    }

    // ---------------- WAV ----------------

    @Test public void wavChunkDissectionAndPaddedBitDepth() throws Exception {
        int sr = 44100, n = sr;
        Random rnd = new Random(3);
        ByteArrayOutputStream pcm = new ByteArrayOutputStream();
        for (int i = 0; i < n; i++) {
            for (int c = 0; c < 2; c++) {
                int s16 = (int) (Math.sin(i * 0.05 + c) * 12000 + rnd.nextGaussian() * 2000);
                int s24 = s16 << 8;
                pcm.write(s24 & 0xFF);
                pcm.write((s24 >> 8) & 0xFF);
                pcm.write((s24 >> 16) & 0xFF);
            }
        }
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.write(ascii("WAVE"));
        body.write(chunk("fmt ", fmt24(sr)));
        ByteArrayOutputStream list = new ByteArrayOutputStream();
        list.write(ascii("INFO"));
        list.write(chunk("ISFT", z("Lavf60.16.100")));
        list.write(chunk("ICMT", z("rendered for suno.com upload")));
        body.write(chunk("LIST", list.toByteArray()));
        byte[] bext = new byte[602];
        System.arraycopy(ascii("Pro Tools"), 0, bext, 256, 9);
        body.write(chunk("bext", bext));
        byte[] junk = new byte[64];
        System.arraycopy(ascii("left-behind-session-id"), 0, junk, 10, 22);
        body.write(chunk("JUNK", junk));
        body.write(chunk("data", pcm.toByteArray()));
        ByteArrayOutputStream file = new ByteArrayOutputStream();
        file.write(ascii("RIFF"));
        file.write(le32(body.size()));
        file.write(body.toByteArray());
        file.write(ascii("TRAILING-SECRET"));
        File wav = temp("probe.wav", file.toByteArray());

        ForensicReport r = AudioForensics.examine(wav, new AudioForensics.Options(), null);
        assertEquals("RIFF/WAVE", r.container);
        assertEquals("fmt,LIST,bext,JUNK,data", r.fingerprint.get("riff.chunkOrder"));
        assertEquals("Lavf60.16.100", r.fingerprint.get("encoder"));
        assertTrue(hasField(r, "Originator", "Pro Tools"));
        assertTrue(hasEvidence(r, Evidence.Tier.SUPPORTING, "Padded bit depth: 16-bit audio in a 24-bit file"));
        assertTrue(hasEvidence(r, Evidence.Tier.SUPPORTING, "Non-zero bytes in 'JUNK'"));
        assertTrue(hasEvidence(r, Evidence.Tier.SUPPORTING, "Data appended after the RIFF container"));
        assertTrue(hasEvidence(r, Evidence.Tier.SUPPORTING, "'suno.com'"));
        assertFalse(r.fields(ForensicReport.SECTION_SIGNAL).isEmpty());
    }

    // ---------------- signal ----------------

    @Test public void signalFindsBandLimitAndRepeatedAudio() throws Exception {
        int sr = 44100, n = sr * 8;
        float[] l = new float[n], rr = new float[n];
        Random rnd = new Random(11);
        int tones = 400;
        double[] freq = new double[tones], phase = new double[tones];
        for (int k = 0; k < tones; k++) { freq[k] = 100 + rnd.nextDouble() * 14900; phase[k] = rnd.nextDouble() * Math.PI * 2; }
        for (int i = 0; i < n; i++) {
            double v = 0;
            for (int k = 0; k < tones; k++) v += Math.sin(2 * Math.PI * freq[k] * i / sr + phase[k]);
            l[i] = (float) (v / tones * 4);
            rr[i] = l[i] * 0.8f;
        }
        System.arraycopy(l, sr, l, sr * 5 + 123, sr);
        System.arraycopy(rr, sr, rr, sr * 5 + 123, sr);
        PcmAudio pcm = new PcmAudio(new float[][] {l, rr}, sr, n, "test generator (exact samples)", 0, 0, false);
        ForensicReport report = new ForensicReport();
        Scan s = new Scan(report, null, 0);
        s.payloadKind = "WAV data chunk";
        SignalAnalyzer.analyze(s, pcm);
        int cutoff = Integer.parseInt(report.fingerprint.get("signal.cutoffHz"));
        assertTrue("cutoff near 15 kHz, was " + cutoff, cutoff >= 14500 && cutoff <= 15500);
        assertTrue(hasEvidence(report, Evidence.Tier.SUPPORTING, "lossy-style"));
        assertTrue(hasEvidence(report, Evidence.Tier.SUPPORTING, "Sample-identical repeated audio"));
    }

    // ---------------- strings & fingerprints ----------------

    @Test public void textForensicsRespectsWordBoundariesAndDecodesBase64() {
        ForensicReport r = new ForensicReport();
        TextForensics t = new TextForensics(r);
        t.inspect("test", "studio", "Recorded at Abbey Road Studios", -1);
        assertFalse(hasEvidence(r, Evidence.Tier.SUPPORTING, "'udio'"));
        String b64 = Bin.base64Encode("{\"generator\":\"suno\",\"id\":\"0f8fad5b-d9cb-469f-a165-70867728950e\"}".getBytes(StandardCharsets.UTF_8));
        t.inspect("test", "blob", b64, -1);
        assertTrue(hasField(r, "", "0f8fad5b-d9cb-469f-a165-70867728950e"));
        assertTrue(hasEvidence(r, Evidence.Tier.SUPPORTING, "'suno'"));
        t.inspect("test", "zw", "Title​with​marks", -1);
        assertTrue(hasEvidence(r, Evidence.Tier.SUPPORTING, "Invisible Unicode"));
    }

    @Test public void fingerprintComparisonIsWeighted() throws Exception {
        Fingerprint a = new Fingerprint();
        a.put("encoder", "LAME3.100");
        a.put("riff.chunkOrder", "fmt,data");
        a.put("mpeg.sampleRate", "44100");
        Fingerprint b = new Fingerprint();
        b.put("encoder", "LAME3.100");
        b.put("riff.chunkOrder", "fmt,LIST,data");
        b.put("mpeg.sampleRate", "44100");
        Fingerprint.Comparison c = a.compareTo(new Fingerprint.Reference("x", "ref", "f", 0, b));
        assertEquals(5, c.matchedWeight);
        assertEquals(9, c.totalWeight);
        File dir = Files.createTempDirectory("fp").toFile();
        Fingerprint.Store store = new Fingerprint.Store(dir);
        Fingerprint.Reference saved = store.save("Label", "file.mp3", a);
        assertEquals(1, store.list().size());
        assertEquals("LAME3.100", store.list().get(0).fingerprint.get("encoder"));
        assertTrue(store.delete(saved.id));
        assertTrue(store.list().isEmpty());
    }

    @Test public void lameCrcAndExtendedFloatHelpers() {
        assertEquals(0xBB3D, MpegStreamParser.crc16("123456789".getBytes(StandardCharsets.US_ASCII), 0, 9));
        byte[] rate44100 = {0x40, 0x0E, (byte) 0xAC, 0x44, 0, 0, 0, 0, 0, 0};
        assertEquals(44100.0, IffParser.extended(rate44100, 0), 1e-6);
    }

    // ---------------- helpers ----------------

    private static boolean hasEvidence(ForensicReport r, Evidence.Tier tier, String titlePart) {
        for (Evidence e : r.evidence) if (e.tier == tier && e.title.contains(titlePart)) return true;
        return false;
    }

    private static boolean hasField(ForensicReport r, String keyPart, String valuePart) {
        for (ForensicReport.Field f : r.fields) if (f.key.contains(keyPart) && f.value.contains(valuePart)) return true;
        return false;
    }

    private static File fixture(String name) throws Exception {
        try (InputStream in = AudioForensicsTest.class.getResourceAsStream("/forensics/" + name)) {
            assertNotNull("missing test fixture " + name, in);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) != -1) out.write(buf, 0, n);
            return temp(name, out.toByteArray());
        }
    }

    private static File temp(String name, byte[] data) throws Exception {
        File dir = Files.createTempDirectory("forensics-test").toFile();
        File f = new File(dir, name);
        try (FileOutputStream out = new FileOutputStream(f)) { out.write(data); }
        return f;
    }

    private static byte[] readAll(File f) throws Exception { return Files.readAllBytes(f.toPath()); }

    private static int indexOf(byte[] b, String s) {
        byte[] n = s.getBytes(StandardCharsets.US_ASCII);
        outer:
        for (int i = 0; i + n.length <= b.length; i++) {
            for (int j = 0; j < n.length; j++) if (b[i + j] != n[j]) continue outer;
            return i;
        }
        return -1;
    }

    private static String sha256(byte[] b) throws Exception { return Bin.hex(MessageDigest.getInstance("SHA-256").digest(b)); }

    private static byte[] derToRaw(byte[] der, int n) {
        int p = 2;
        if ((der[1] & 0x80) != 0) p += der[1] & 0x7F;
        byte[] out = new byte[2 * n];
        for (int k = 0; k < 2; k++) {
            int len = der[p + 1];
            int start = p + 2;
            int copy = Math.min(len, n);
            System.arraycopy(der, start + len - copy, out, k * n + (n - copy), copy);
            p = start + len;
        }
        return out;
    }

    private static byte[] mpegFrame(Random rnd) {
        byte[] f = new byte[417];
        for (int i = 4; i < f.length; i++) f[i] = (byte) rnd.nextInt(200);
        f[0] = (byte) 0xFF;
        f[1] = (byte) 0xFB;
        f[2] = (byte) 0x90;
        f[3] = (byte) 0x44;
        return f;
    }

    private static byte[] id3v23() throws Exception {
        ByteArrayOutputStream frames = new ByteArrayOutputStream();
        frames.write(id3Frame("TIT2", cat(new byte[] {0}, ascii("Night Drive"))));
        frames.write(id3Frame("TXXX", cat(new byte[] {0}, ascii("generator"), new byte[] {0}, ascii("Example Generator 2"))));
        frames.write(id3Frame("TSSE", cat(new byte[] {0}, ascii("Lavf60.16.100"))));
        frames.write(id3Frame("PRIV", cat(ascii("com.suno.app"), new byte[] {0}, ascii("{\"clip\":\"6f1c2a9e-3b4d-4e5f-8a9b-0c1d2e3f4a5b\"}"))));
        byte[] padding = new byte[32];
        padding[20] = 0x42;
        frames.write(padding);
        byte[] body = frames.toByteArray();
        ByteArrayOutputStream tag = new ByteArrayOutputStream();
        tag.write(ascii("ID3"));
        tag.write(new byte[] {3, 0, 0});
        int size = body.length;
        tag.write(new byte[] {(byte) ((size >> 21) & 0x7F), (byte) ((size >> 14) & 0x7F), (byte) ((size >> 7) & 0x7F), (byte) (size & 0x7F)});
        tag.write(body);
        return tag.toByteArray();
    }

    private static byte[] id3Frame(String id, byte[] data) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(ascii(id));
        out.write(new byte[] {(byte) (data.length >> 24), (byte) (data.length >> 16), (byte) (data.length >> 8), (byte) data.length, 0, 0});
        out.write(data);
        return out.toByteArray();
    }

    private static byte[] apeTag() throws Exception {
        byte[] value = ascii("APE Artist");
        ByteArrayOutputStream item = new ByteArrayOutputStream();
        item.write(le32(value.length));
        item.write(le32(0));
        item.write(ascii("ARTIST"));
        item.write(0);
        item.write(value);
        byte[] items = item.toByteArray();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(items);
        out.write(ascii("APETAGEX"));
        out.write(le32(2000));
        out.write(le32(items.length + 32));
        out.write(le32(1));
        out.write(le32(0));
        out.write(new byte[8]);
        return out.toByteArray();
    }

    private static byte[] id3v1(String title) {
        byte[] t = new byte[128];
        System.arraycopy(ascii("TAG"), 0, t, 0, 3);
        System.arraycopy(ascii(title), 0, t, 3, title.length());
        t[127] = (byte) 255;
        return t;
    }

    private static byte[] fmt24(int sr) {
        byte[] f = new byte[16];
        f[0] = 1;
        f[2] = 2;
        put32(f, 4, sr);
        put32(f, 8, sr * 6);
        f[12] = 6;
        f[14] = 24;
        return f;
    }

    private static byte[] chunk(String id, byte[] data) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(ascii(id));
        out.write(le32(data.length));
        out.write(data);
        if (data.length % 2 == 1) out.write(0);
        return out.toByteArray();
    }

    private static byte[] z(String s) { return cat(ascii(s), new byte[] {0}); }
    private static byte[] ascii(String s) { return s.getBytes(StandardCharsets.US_ASCII); }

    private static byte[] le32(int v) { return new byte[] {(byte) v, (byte) (v >> 8), (byte) (v >> 16), (byte) (v >> 24)}; }

    private static void put32(byte[] b, int o, int v) {
        b[o] = (byte) v;
        b[o + 1] = (byte) (v >> 8);
        b[o + 2] = (byte) (v >> 16);
        b[o + 3] = (byte) (v >> 24);
    }

    private static byte[] cat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] p : parts) out.write(p, 0, p.length);
        return out.toByteArray();
    }
}
