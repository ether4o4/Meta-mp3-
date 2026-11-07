package com.whitetea.baretrack.forensics;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Parses a C2PA manifest store (JUMBF), decodes the active claim and assertions, verifies the COSE_Sign1
 * claim signature, the assertion hashes and the c2pa.hash.data content binding — entirely offline.
 *
 * What it cannot do offline: check the signer against the C2PA/Suno trust lists, or check revocation.
 * Those are what the official verifier adds, so a mathematically valid signature is reported as
 * "intact", not as confirmed identity, unless the signer matches a certificate you pinned yourself.
 */
public final class C2paInspector {
    static final byte[] C2PA_STORE_UUID = hexBytes("6332706100110010800000aa00389b71");

    public static final class Result {
        public String source = "";
        public int manifestCount;
        public String activeManifest = "";
        public String claimVersion = "";
        public String claimGenerator = "";
        public String title = "";
        public String format = "";
        public String instanceId = "";
        public String signatureAlg = "";
        public String signer = "";
        public String issuer = "";
        public String signerSha256 = "";
        public String rootSubject = "";
        public String certValidity = "";
        public boolean chainConsistent;
        public boolean signaturePresent;
        public Boolean signatureValid;
        public String signatureStatus = "not checked";
        public Boolean assertionHashesValid;
        public String assertionHashStatus = "not checked";
        public Boolean bindingValid;
        public String bindingStatus = "no c2pa.hash.data assertion";
        public String digitalSourceType = "";
        public String softBinding = "";
        public final List<String> assertions = new ArrayList<>();
        public final List<String> actions = new ArrayList<>();
        public final List<String> problems = new ArrayList<>();

        public boolean namesSuno() {
            String all = (claimGenerator + " " + signer + " " + issuer + " " + softBinding + " " + String.valueOf(actions)).toLowerCase(Locale.ROOT);
            return all.contains("suno");
        }

        public boolean aiDeclared() { return digitalSourceType.toLowerCase(Locale.ROOT).contains("algorithmicmedia"); }

        public boolean intact() {
            return Boolean.TRUE.equals(signatureValid) && !Boolean.FALSE.equals(assertionHashesValid) && Boolean.TRUE.equals(bindingValid);
        }
    }

    static final class Box {
        String type;
        int start;
        int contentStart;
        int end;
        String label = "";
        byte[] uuid;
        final List<Box> children = new ArrayList<>();
        int descEnd;

        boolean isSuper() { return "jumb".equals(type); }

        Box child(String wanted) {
            for (Box c : children) if (c.isSuper() && wanted.equals(c.label)) return c;
            return null;
        }

        Box firstContent(String wantedType) {
            for (Box c : children) if (wantedType.equals(c.type)) return c;
            return null;
        }
    }

    private C2paInspector() {}

    /** Parse a JUMBF manifest store. file/fileOffset are used to verify the hash binding against the whole file. */
    static Result inspectStore(byte[] store, RandomAccessFile file, long storeFileOffset, ForensicReport report, String source) {
        Result r = new Result();
        r.source = source;
        List<Box> top;
        try {
            top = parse(store, 0, store.length, 0);
        } catch (IOException e) {
            report.field(ForensicReport.SECTION_C2PA, source, "Parse error", e.getMessage(), storeFileOffset);
            return null;
        }
        Box root = null;
        for (Box b : top) if (b.isSuper() && ("c2pa".equals(b.label) || Arrays.equals(C2PA_STORE_UUID, b.uuid))) root = b;
        if (root == null) {
            report.field(ForensicReport.SECTION_C2PA, source, "JUMBF", "present but no 'c2pa' manifest store label", storeFileOffset);
            return null;
        }
        report.blob("C2PA manifest store (" + source + ")", "application/c2pa", "manifest.c2pa", store);
        List<Box> manifests = new ArrayList<>();
        for (Box c : root.children) if (c.isSuper()) manifests.add(c);
        r.manifestCount = manifests.size();
        report.field(ForensicReport.SECTION_C2PA, source, "Manifest store", store.length + " bytes, " + manifests.size() + " manifest(s)", storeFileOffset);
        if (manifests.isEmpty()) return r;
        for (int i = 0; i < manifests.size(); i++) {
            report.field(ForensicReport.SECTION_C2PA, source, "Manifest " + (i + 1) + (i == manifests.size() - 1 ? " (active)" : ""),
                    manifests.get(i).label, storeFileOffset < 0 ? -1 : storeFileOffset + manifests.get(i).start);
        }
        Box active = manifests.get(manifests.size() - 1);
        r.activeManifest = active.label;
        try {
            decodeManifest(store, active, r, file, report, source, storeFileOffset);
        } catch (Exception e) {
            r.problems.add("Manifest decode failed: " + e.getMessage());
        }
        for (String p : r.problems) report.field(ForensicReport.SECTION_C2PA, source, "Problem", p, -1);
        return r;
    }

    private static void decodeManifest(byte[] d, Box manifest, Result r, RandomAccessFile file, ForensicReport report,
                                       String source, long storeOffset) throws IOException {
        Box claimBox = manifest.child("c2pa.claim.v2");
        r.claimVersion = claimBox != null ? "v2" : "v1";
        if (claimBox == null) claimBox = manifest.child("c2pa.claim");
        Box assertionStore = manifest.child("c2pa.assertions");
        Box sigBox = manifest.child("c2pa.signature");
        byte[] claimBytes = null;
        Object claim = null;
        if (claimBox != null) {
            Box cb = claimBox.firstContent("cbor");
            if (cb != null) {
                claimBytes = Arrays.copyOfRange(d, cb.contentStart, cb.end);
                claim = Cbor.decode(claimBytes);
            }
        }
        if (claim == null) r.problems.add("No claim found in the active manifest.");

        if (claim != null) {
            String gen = Cbor.text(claim, "claim_generator");
            Object info = Cbor.get(claim, "claim_generator_info");
            StringBuilder g = new StringBuilder(gen == null ? "" : gen);
            List<Object> infos = new ArrayList<>();
            if (info instanceof List) infos.addAll((List<?>) info);
            else if (info != null) infos.add(info);
            for (Object o : infos) {
                String name = Cbor.text(o, "name"), ver = Cbor.text(o, "version");
                if (name != null) {
                    if (g.length() > 0) g.append(" | ");
                    g.append(name).append(ver == null ? "" : " " + ver);
                }
            }
            r.claimGenerator = g.toString();
            r.title = nz(Cbor.text(claim, "dc:title"));
            r.format = nz(Cbor.text(claim, "dc:format"));
            r.instanceId = nz(Cbor.text(claim, "instanceID"));
            report.field(ForensicReport.SECTION_C2PA, source, "Claim version", r.claimVersion, -1);
            report.field(ForensicReport.SECTION_C2PA, source, "Claim generator", r.claimGenerator, -1);
            if (!r.title.isEmpty()) report.field(ForensicReport.SECTION_C2PA, source, "dc:title", r.title, -1);
            if (!r.format.isEmpty()) report.field(ForensicReport.SECTION_C2PA, source, "dc:format", r.format, -1);
            if (!r.instanceId.isEmpty()) report.field(ForensicReport.SECTION_C2PA, source, "instanceID", r.instanceId, -1);
            report.field(ForensicReport.SECTION_C2PA, source, "Claim (decoded)", Cbor.display(claim, 1500), -1);
        }

        // Assertions
        if (assertionStore != null) {
            for (Box a : assertionStore.children) {
                if (!a.isSuper()) continue;
                r.assertions.add(a.label);
                Object value = null;
                Box content = a.firstContent("cbor");
                if (content != null) {
                    try { value = Cbor.decode(d, content.contentStart, content.end); } catch (IOException ignored) { }
                }
                String rendered;
                if (value != null) rendered = Cbor.display(value, 1200);
                else {
                    Box json = a.firstContent("json");
                    rendered = json != null ? Bin.utf8(d, json.contentStart, json.end - json.contentStart) : "(" + (a.end - a.start) + " bytes, non-CBOR)";
                }
                report.field(ForensicReport.SECTION_C2PA, source, "Assertion " + a.label, rendered, storeOffset < 0 ? -1 : storeOffset + a.start);
                if (a.label.startsWith("c2pa.actions")) actions(value, r);
                if (a.label.startsWith("c2pa.soft-binding")) {
                    r.softBinding = nz(Cbor.text(value, "alg"));
                    report.field(ForensicReport.SECTION_C2PA, source, "Soft binding (watermark/fingerprint) algorithm", r.softBinding, -1);
                }
                if (a.label.equals("c2pa.hash.data") || a.label.startsWith("c2pa.hash.data.")) verifyDataHash(value, file, r);
                if (a.label.startsWith("c2pa.hash.bmff")) {
                    r.bindingStatus = "BMFF (MP4) hash binding present — not verified by this build; use the official verifier";
                }
                if (a.label.startsWith("c2pa.hash.collection") || a.label.startsWith("c2pa.hash.boxes")) {
                    r.bindingStatus = a.label + " binding present — not verified by this build; use the official verifier";
                }
            }
            if (claim != null) verifyAssertionHashes(d, claim, assertionStore, r);
        } else {
            r.problems.add("No assertion store in the active manifest.");
        }
        report.field(ForensicReport.SECTION_C2PA, source, "Assertion hashes", r.assertionHashStatus, -1);
        report.field(ForensicReport.SECTION_C2PA, source, "Content binding", r.bindingStatus, -1);
        if (!r.digitalSourceType.isEmpty()) report.field(ForensicReport.SECTION_C2PA, source, "digitalSourceType", r.digitalSourceType, -1);

        // Signature
        if (sigBox != null) {
            Box cb = sigBox.firstContent("cbor");
            if (cb != null) {
                r.signaturePresent = true;
                verifySignature(Cbor.decode(d, cb.contentStart, cb.end), claimBytes, r);
            }
        }
        if (!r.signaturePresent) r.signatureStatus = "no claim signature box";
        report.field(ForensicReport.SECTION_C2PA, source, "Signature algorithm", r.signatureAlg, -1);
        report.field(ForensicReport.SECTION_C2PA, source, "Signer certificate subject", r.signer, -1);
        report.field(ForensicReport.SECTION_C2PA, source, "Signer certificate issuer", r.issuer, -1);
        report.field(ForensicReport.SECTION_C2PA, source, "Signer certificate SHA-256", r.signerSha256, -1);
        if (!r.rootSubject.isEmpty()) report.field(ForensicReport.SECTION_C2PA, source, "Chain root", r.rootSubject + (r.chainConsistent ? " (chain links verify)" : " (chain links do NOT verify)"), -1);
        if (!r.certValidity.isEmpty()) report.field(ForensicReport.SECTION_C2PA, source, "Certificate validity", r.certValidity, -1);
        report.field(ForensicReport.SECTION_C2PA, source, "Signature", r.signatureStatus, -1);
    }

    private static void actions(Object value, Result r) {
        Object list = Cbor.get(value, "actions");
        if (!(list instanceof List)) return;
        for (Object a : (List<?>) list) {
            String action = nz(Cbor.text(a, "action"));
            String dst = Cbor.text(a, "digitalSourceType");
            Object agent = Cbor.get(a, "softwareAgent");
            String agentText = agent instanceof String ? (String) agent : (agent instanceof Map ? nz(Cbor.text(agent, "name")) + " " + nz(Cbor.text(agent, "version")) : "");
            r.actions.add(action + (agentText.trim().isEmpty() ? "" : " by " + agentText.trim()) + (dst == null ? "" : " [" + dst + "]"));
            if (dst != null && r.digitalSourceType.isEmpty()) r.digitalSourceType = dst;
        }
    }

    private static void verifyDataHash(Object value, RandomAccessFile file, Result r) {
        if (value == null) { r.bindingStatus = "c2pa.hash.data could not be decoded"; r.bindingValid = false; return; }
        Object expected = Cbor.get(value, "hash");
        String alg = Cbor.text(value, "alg");
        if (alg == null) alg = "sha256";
        if (!(expected instanceof byte[])) { r.bindingStatus = "c2pa.hash.data has no hash value"; r.bindingValid = false; return; }
        if (file == null) { r.bindingStatus = "c2pa.hash.data present; file bytes unavailable for checking"; return; }
        List<long[]> exclusions = new ArrayList<>();
        Object ex = Cbor.get(value, "exclusions");
        if (ex instanceof List) {
            for (Object e : (List<?>) ex) {
                Object s = Cbor.get(e, "start"), l = Cbor.get(e, "length");
                if (s instanceof Number && l instanceof Number) exclusions.add(new long[] {((Number) s).longValue(), ((Number) l).longValue()});
            }
        }
        try {
            MessageDigest md = MessageDigest.getInstance(javaHash(alg));
            long len = file.length();
            long pos = 0;
            java.util.Collections.sort(exclusions, (a, b) -> Long.compare(a[0], b[0]));
            byte[] buf = new byte[64 * 1024];
            for (long[] e : exclusions) {
                hashRange(file, pos, Math.min(e[0], len), md, buf);
                pos = Math.max(pos, e[0] + e[1]);
            }
            hashRange(file, pos, len, md, buf);
            byte[] actual = md.digest();
            r.bindingValid = MessageDigest.isEqual(actual, (byte[]) expected);
            StringBuilder ranges = new StringBuilder();
            for (long[] e : exclusions) ranges.append(String.format(Locale.ROOT, " [0x%X+%d]", e[0], e[1]));
            r.bindingStatus = (r.bindingValid ? "MATCH — audio bytes are unchanged since signing" : "MISMATCH — bytes changed after signing")
                    + " (" + alg + ", exclusions" + (ranges.length() == 0 ? " none" : ranges) + ")";
        } catch (Exception e) {
            r.bindingStatus = "binding check failed: " + e.getMessage();
        }
    }

    private static void hashRange(RandomAccessFile f, long from, long to, MessageDigest md, byte[] buf) throws IOException {
        f.seek(from);
        long left = to - from;
        while (left > 0) {
            int n = (int) Math.min(buf.length, left);
            f.readFully(buf, 0, n);
            md.update(buf, 0, n);
            left -= n;
        }
    }

    private static void verifyAssertionHashes(byte[] d, Object claim, Box store, Result r) {
        List<Object> refs = new ArrayList<>();
        for (String key : new String[] {"assertions", "created_assertions", "gathered_assertions"}) {
            Object v = Cbor.get(claim, key);
            if (v instanceof List) refs.addAll((List<?>) v);
        }
        if (refs.isEmpty()) { r.assertionHashStatus = "claim lists no hashed assertions"; return; }
        String claimAlg = Cbor.text(claim, "alg");
        int ok = 0, bad = 0, missing = 0;
        StringBuilder failures = new StringBuilder();
        for (Object ref : refs) {
            String url = Cbor.text(ref, "url");
            Object hash = Cbor.get(ref, "hash");
            String alg = Cbor.text(ref, "alg");
            if (alg == null) alg = claimAlg == null ? "sha256" : claimAlg;
            if (url == null || !(hash instanceof byte[])) continue;
            String label = url.substring(url.lastIndexOf('/') + 1);
            Box target = store.child(label);
            if (target == null) { missing++; failures.append(" missing:").append(label); continue; }
            try {
                MessageDigest md = MessageDigest.getInstance(javaHash(alg));
                byte[] whole = md.digest(Arrays.copyOfRange(d, target.start, target.end));
                byte[] inner = md.digest(Arrays.copyOfRange(d, target.contentStart, target.end));
                if (MessageDigest.isEqual(whole, (byte[]) hash) || MessageDigest.isEqual(inner, (byte[]) hash)) ok++;
                else { bad++; failures.append(" mismatch:").append(label); }
            } catch (Exception e) {
                bad++;
                failures.append(" error:").append(label);
            }
        }
        r.assertionHashesValid = bad == 0 && missing == 0 && ok > 0;
        r.assertionHashStatus = String.format(Locale.ROOT, "%d verified, %d mismatched, %d missing%s", ok, bad, missing, failures);
    }

    private static void verifySignature(Object cose, byte[] claimBytes, Result r) {
        Object body = Cbor.untag(cose);
        if (!(body instanceof List) || ((List<?>) body).size() != 4) { r.signatureStatus = "signature is not a COSE_Sign1 structure"; r.signatureValid = false; return; }
        List<?> parts = (List<?>) body;
        byte[] protectedBytes = parts.get(0) instanceof byte[] ? (byte[]) parts.get(0) : new byte[0];
        Object unprotected = parts.get(1);
        Object payload = parts.get(2);
        Object sig = parts.get(3);
        Object prot;
        try { prot = protectedBytes.length == 0 ? null : Cbor.decode(protectedBytes); } catch (IOException e) { prot = null; }
        Object algObj = Cbor.get(prot, 1L);
        long alg = algObj instanceof Number ? ((Number) algObj).longValue() : 0;
        r.signatureAlg = coseAlgName(alg);

        List<byte[]> chain = new ArrayList<>();
        for (Object headers : new Object[] {prot, unprotected}) {
            for (Object key : new Object[] {33L, "x5chain"}) {
                Object x5 = Cbor.get(headers, key);
                if (x5 instanceof byte[]) chain.add((byte[]) x5);
                else if (x5 instanceof List) for (Object c : (List<?>) x5) if (c instanceof byte[]) chain.add((byte[]) c);
            }
            if (!chain.isEmpty()) break;
        }
        if (chain.isEmpty()) { r.signatureStatus = "no x5chain certificate in the signature"; r.signatureValid = false; return; }
        X509Certificate[] certs = new X509Certificate[chain.size()];
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            for (int i = 0; i < chain.size(); i++) certs[i] = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(chain.get(i)));
        } catch (Exception e) {
            r.signatureStatus = "signer certificate could not be parsed: " + e.getMessage();
            r.signatureValid = false;
            return;
        }
        X509Certificate leaf = certs[0];
        r.signer = leaf.getSubjectX500Principal().getName();
        r.issuer = leaf.getIssuerX500Principal().getName();
        r.signerSha256 = ImageInspector.sha256(chain.get(0));
        r.certValidity = leaf.getNotBefore() + " → " + leaf.getNotAfter();
        boolean consistent = true;
        for (int i = 0; i + 1 < certs.length; i++) {
            try { certs[i].verify(certs[i + 1].getPublicKey()); } catch (Exception e) { consistent = false; }
        }
        r.chainConsistent = consistent;
        r.rootSubject = certs[certs.length - 1].getIssuerX500Principal().getName();

        byte[] data = payload instanceof byte[] ? (byte[]) payload : claimBytes;
        if (data == null) { r.signatureStatus = "claim bytes unavailable"; r.signatureValid = false; return; }
        if (!(sig instanceof byte[])) { r.signatureStatus = "signature value missing"; r.signatureValid = false; return; }
        byte[] toBeSigned = Cbor.encodeSigStructure("Signature1", protectedBytes, new byte[0], data);
        try {
            boolean valid = verify(alg, leaf.getPublicKey(), toBeSigned, (byte[]) sig);
            r.signatureValid = valid;
            r.signatureStatus = valid
                    ? "VALID — the claim is signed by this certificate's key and unaltered (trust list and revocation not checked offline)"
                    : "INVALID — the claim does not match its signature";
        } catch (UnsupportedOperationException e) {
            r.signatureStatus = "algorithm " + r.signatureAlg + " is not supported on this device: " + e.getMessage();
        } catch (Exception e) {
            r.signatureStatus = "verification error: " + e.getMessage();
            r.signatureValid = false;
        }
    }

    static boolean verify(long alg, PublicKey key, byte[] data, byte[] sig) throws Exception {
        Signature s;
        byte[] signature = sig;
        if (alg == -7 || alg == -35 || alg == -36) {
            s = Signature.getInstance(alg == -7 ? "SHA256withECDSA" : alg == -35 ? "SHA384withECDSA" : "SHA512withECDSA");
            signature = rawToDer(sig);
        } else if (alg == -37 || alg == -38 || alg == -39) {
            String hash = alg == -37 ? "SHA-256" : alg == -38 ? "SHA-384" : "SHA-512";
            int saltLen = alg == -37 ? 32 : alg == -38 ? 48 : 64;
            String name = alg == -37 ? "SHA256withRSA/PSS" : alg == -38 ? "SHA384withRSA/PSS" : "SHA512withRSA/PSS";
            try {
                s = Signature.getInstance(name);
            } catch (Exception android) {
                s = Signature.getInstance("RSASSA-PSS");
                s.setParameter(new PSSParameterSpec(hash, "MGF1", new MGF1ParameterSpec(hash), saltLen, 1));
            }
        } else if (alg == -8) {
            try { s = Signature.getInstance("Ed25519"); } catch (Exception e) { throw new UnsupportedOperationException("Ed25519 unavailable"); }
        } else {
            throw new UnsupportedOperationException("COSE alg " + alg);
        }
        s.initVerify(key);
        s.update(data);
        return s.verify(signature);
    }

    /** COSE ECDSA signatures are r||s; Java expects ASN.1 DER. */
    static byte[] rawToDer(byte[] raw) {
        if (raw.length > 0 && raw[0] == 0x30) return raw;
        int n = raw.length / 2;
        byte[] r = new BigInteger(1, Arrays.copyOfRange(raw, 0, n)).toByteArray();
        byte[] s = new BigInteger(1, Arrays.copyOfRange(raw, n, raw.length)).toByteArray();
        java.io.ByteArrayOutputStream body = new java.io.ByteArrayOutputStream();
        derInt(body, r);
        derInt(body, s);
        byte[] b = body.toByteArray();
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        out.write(0x30);
        derLen(out, b.length);
        out.write(b, 0, b.length);
        return out.toByteArray();
    }

    private static void derInt(java.io.ByteArrayOutputStream out, byte[] v) {
        out.write(0x02);
        derLen(out, v.length);
        out.write(v, 0, v.length);
    }

    private static void derLen(java.io.ByteArrayOutputStream out, int len) {
        if (len < 128) out.write(len);
        else if (len < 256) { out.write(0x81); out.write(len); }
        else { out.write(0x82); out.write(len >> 8); out.write(len & 0xFF); }
    }

    static String coseAlgName(long alg) {
        switch ((int) alg) {
            case -7: return "ES256";
            case -35: return "ES384";
            case -36: return "ES512";
            case -37: return "PS256";
            case -38: return "PS384";
            case -39: return "PS512";
            case -8: return "Ed25519";
            case 0: return "unspecified";
            default: return "COSE " + alg;
        }
    }

    private static String javaHash(String alg) {
        String a = alg.toLowerCase(Locale.ROOT).replace("-", "");
        if (a.equals("sha384")) return "SHA-384";
        if (a.equals("sha512")) return "SHA-512";
        return "SHA-256";
    }

    // ---- JUMBF ----

    static List<Box> parse(byte[] d, int start, int end, int depth) throws IOException {
        List<Box> out = new ArrayList<>();
        if (depth > 16) throw new IOException("JUMBF nesting too deep");
        int p = start;
        while (p + 8 <= end) {
            long lbox = Bin.u32be(d, p);
            String type = Bin.fourcc(d, p + 4);
            int header = 8;
            long size = lbox;
            if (lbox == 1) {
                if (p + 16 > end) throw new IOException("truncated XLBox");
                size = Bin.u64be(d, p + 8);
                header = 16;
            } else if (lbox == 0) size = end - p;
            if (size < header || p + size > end) throw new IOException("box '" + type + "' overruns its parent at " + p);
            Box b = new Box();
            b.type = type;
            b.start = p;
            b.contentStart = p + header;
            b.end = (int) (p + size);
            if (b.isSuper()) {
                List<Box> kids = parse(d, b.contentStart, b.end, depth + 1);
                if (!kids.isEmpty() && "jumd".equals(kids.get(0).type)) {
                    Box desc = kids.get(0);
                    int q = desc.contentStart;
                    if (q + 17 <= desc.end) {
                        b.uuid = Arrays.copyOfRange(d, q, q + 16);
                        int toggles = d[q + 16] & 0xFF;
                        q += 17;
                        if ((toggles & 0x02) != 0) {
                            int z = q;
                            while (z < desc.end && d[z] != 0) z++;
                            b.label = new String(d, q, z - q, StandardCharsets.UTF_8);
                        }
                    }
                    for (int i = 1; i < kids.size(); i++) b.children.add(kids.get(i));
                } else b.children.addAll(kids);
            }
            out.add(b);
            p = b.end;
        }
        return out;
    }

    /** Locate a JUMBF 'c2pa' store anywhere in a byte region (fallback for unknown carriers). */
    static int findStore(byte[] d) {
        for (int i = 4; i + 4 <= d.length; i++) {
            if (d[i] == 'j' && d[i + 1] == 'u' && d[i + 2] == 'm' && d[i + 3] == 'b') {
                long size = Bin.u32be(d, i - 4);
                if (size >= 16 && i - 4 + size <= d.length) {
                    try {
                        List<Box> boxes = parse(d, i - 4, (int) (i - 4 + size), 0);
                        if (!boxes.isEmpty() && "c2pa".equals(boxes.get(0).label)) return i - 4;
                    } catch (IOException ignored) { }
                }
            }
        }
        return -1;
    }

    private static String nz(String s) { return s == null ? "" : s; }

    static byte[] hexBytes(String hex) {
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        return out;
    }
}
