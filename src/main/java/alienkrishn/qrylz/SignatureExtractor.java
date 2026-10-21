package alienkrishn.qrylz;

import com.reandroid.apk.ApkModule;
import com.reandroid.archive.block.ApkSignatureBlock;
import com.reandroid.archive.block.CertificateBlock;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

/**
 * Reads the signing certificate and the original {@code META-INF} folder out of an APK.
 * <p>
 * The certificate is needed in two shapes:
 * <ul>
 *   <li>Base64 of the DER encoding - embedded into the payload dex so the runtime proxy
 *       can rebuild an {@code android.content.pm.Signature} from it.</li>
 *   <li>The raw {@code META-INF} entries - zipped into a tiny archive that is injected
 *       into {@code assets/} so the native hook can serve the original signature blocks
 *       to code that reads the APK file directly.</li>
 * </ul>
 */
public final class SignatureExtractor {

    /** Name of the tiny archive that is injected into {@code assets/}. */
    public static final String ORIGIN_ARCHIVE = "qrylz_origin.zip";

    /** Entry inside the origin archive that carries the raw certificate. */
    public static final String CERTIFICATE_ENTRY = "qrylz/cert.der";

    private static final String META_INF = "META-INF/";

    private SignatureExtractor() {
    }

    /**
     * Everything the pipeline needs to know about the original signature.
     */
    public static final class SignatureData {

        private final byte[] certificateDer;
        private final String base64;
        private final String sha256;
        private final String certificateEntry;
        private final Map<String, byte[]> metaInf;

        SignatureData(byte[] certificateDer, String base64, String sha256,
                      String certificateEntry, Map<String, byte[]> metaInf) {
            this.certificateDer = certificateDer;
            this.base64 = base64;
            this.sha256 = sha256;
            this.certificateEntry = certificateEntry;
            this.metaInf = Collections.unmodifiableMap(metaInf);
        }

        /** @return DER encoded X.509 certificate */
        public byte[] getCertificateDer() {
            return certificateDer.clone();
        }

        /** @return Base64 of the DER encoded certificate, ready to be embedded in a dex */
        public String getBase64() {
            return base64;
        }

        /** @return lower case hex SHA-256 of the certificate, for logging */
        public String getSha256() {
            return sha256;
        }

        /** @return where the certificate came from, for logging */
        public String getCertificateEntry() {
            return certificateEntry;
        }

        /** @return the original {@code META-INF} entries, keyed by their archive name */
        public Map<String, byte[]> getMetaInf() {
            return metaInf;
        }
    }

    /**
     * Extracts the signing certificate and the top level {@code META-INF} entries.
     * <p>
     * The certificate is looked for in two places, because a modern APK usually carries
     * no v1 signature at all:
     * <ol>
     *   <li>{@code META-INF/CERT.RSA} and friends - the v1 (JAR) signature</li>
     *   <li>the APK signature scheme v2/v3 block - what current tooling produces</li>
     * </ol>
     *
     * @param apk the untouched APK
     * @return the extracted signature data
     * @throws IOException when the APK cannot be read or carries no usable certificate
     */
    public static SignatureData extract(File apk) throws IOException {
        Map<String, byte[]> metaInf = new LinkedHashMap<>();
        String certificateEntry = null;

        try (ZipFile zip = new ZipFile(apk)) {
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                if (entry.isDirectory()) {
                    continue;
                }
                String name = entry.getName();
                if (!name.startsWith(META_INF)) {
                    continue;
                }
                // Only the files that take part in the v1 signature: META-INF/MANIFEST.MF,
                // META-INF/*.SF and META-INF/*.RSA|DSA|EC. Nested folders such as
                // META-INF/services are irrelevant here and would bloat the origin archive.
                if (name.indexOf('/', META_INF.length()) >= 0) {
                    continue;
                }
                byte[] data;
                try (InputStream in = zip.getInputStream(entry)) {
                    data = readAll(in);
                }
                metaInf.put(name, data);
                if (certificateEntry == null && isCertificate(name)) {
                    certificateEntry = name;
                }
            }
        }

        byte[] der;
        if (certificateEntry != null) {
            der = parseCertificate(metaInf.get(certificateEntry));
        } else {
            der = readSignatureBlockCertificate(apk);
            certificateEntry = "APK signature scheme block (v2/v3)";
        }

        String base64 = Base64.getEncoder().encodeToString(der);
        String sha256 = hex(sha256(der));

        return new SignatureData(der, base64, sha256, certificateEntry, metaInf);
    }

    /**
     * Reads the certificate out of the APK signature scheme v2/v3 block.
     * <p>
     * That block sits between the last entry and the central directory and holds the
     * signing certificate in its own format, so it is read through ARSCLib instead of the
     * zip api.
     */
    private static byte[] readSignatureBlockCertificate(File apk) throws IOException {
        try (ApkModule module = ApkModule.loadApkFile(apk)) {
            ApkSignatureBlock block = module.getApkSignatureBlock();
            if (block != null) {
                Iterator<CertificateBlock> certificates = block.getCertificates();
                if (certificates.hasNext()) {
                    return certificates.next().getCertificateBytes();
                }
            }
        }
        throw new IOException("No signing certificate found in " + apk
                + " (neither a v1 META-INF signature nor a v2/v3 signature block)");
    }

    /**
     * Packs the original {@code META-INF} entries into a small zip archive.
     * <p>
     * Only a few kilobytes in a normal APK, which is the whole point of the "tiny
     * origin" trick: the native hook needs the original signature blocks, not a copy of
     * the whole application.
     *
     * @param metaInf the entries as returned by {@link #extract(File)}
     * @return the archive bytes
     * @throws IOException when the archive cannot be written
     */
    public static byte[] buildOriginArchive(Map<String, byte[]> metaInf) throws IOException {
        return buildOriginArchive(metaInf, null);
    }

    /**
     * Packs the original {@code META-INF} entries and the original certificate into a
     * small zip archive.
     * <p>
     * Only a few kilobytes in a normal APK, which is the whole point of the "tiny
     * origin" trick: the native hook needs the original signature material, not a copy
     * of the whole application.
     *
     * @param metaInf the entries as returned by {@link #extract(File)}
     * @param certificateDer the original certificate, may be {@code null}
     * @return the archive bytes
     * @throws IOException when the archive cannot be written
     */
    public static byte[] buildOriginArchive(Map<String, byte[]> metaInf, byte[] certificateDer)
            throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(out)) {
            for (Map.Entry<String, byte[]> entry : metaInf.entrySet()) {
                writeEntry(zip, entry.getKey(), entry.getValue());
            }
            if (certificateDer != null) {
                writeEntry(zip, CERTIFICATE_ENTRY, certificateDer);
            }
        }
        return out.toByteArray();
    }

    private static void writeEntry(ZipOutputStream zip, String name, byte[] data)
            throws IOException {
        ZipEntry zipEntry = new ZipEntry(name);
        // Fixed timestamp so the same input always produces the same archive.
        zipEntry.setTime(0L);
        zip.putNextEntry(zipEntry);
        zip.write(data);
        zip.closeEntry();
    }

    /**
     * Parses the certificate out of a v1 signature block.
     * <p>
     * {@code META-INF/CERT.RSA} is a PKCS#7 SignedData structure. Some tools emit a bare
     * X.509 certificate instead, so both shapes are accepted.
     */
    private static byte[] parseCertificate(byte[] blob) throws IOException {
        CertificateFactory factory;
        try {
            factory = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            throw new IOException("X.509 certificate factory unavailable", e);
        }
        try (InputStream in = new ByteArrayInputStream(blob)) {
            Certificate certificate = factory.generateCertificate(in);
            return certificate.getEncoded();
        } catch (CertificateException primary) {
            try (InputStream in = new ByteArrayInputStream(blob)) {
                java.util.Collection<? extends Certificate> certificates = factory.generateCertificates(in);
                if (certificates.isEmpty()) {
                    throw new IOException("Cannot parse the signing certificate", primary);
                }
                return certificates.iterator().next().getEncoded();
            } catch (CertificateException e) {
                throw new IOException("Cannot parse the signing certificate", e);
            }
        }
    }

    private static boolean isCertificate(String name) {
        String upper = name.toUpperCase(Locale.US);
        return upper.endsWith(".RSA") || upper.endsWith(".DSA") || upper.endsWith(".EC");
    }

    private static byte[] readAll(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int read;
        while ((read = in.read(buffer)) != -1) {
            out.write(buffer, 0, read);
        }
        return out.toByteArray();
    }

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private static String hex(byte[] data) {
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data) {
            sb.append(String.format(Locale.US, "%02x", b));
        }
        return sb.toString();
    }
}
