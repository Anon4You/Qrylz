package alienkrishn.qrylz.payload;

import alienkrishn.qrylz.ApkOverlapper;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public final class QrylzSelfTest {

    private QrylzSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        testOriginRoundTrip();
        testApkPath();
        System.out.println("self-test passed");
    }

    private static void testOriginRoundTrip() throws Exception {
        Path dir = Files.createTempDirectory("qrylz-self-test-");
        try {
            Path original = dir.resolve("original.apk");
            byte[] source = writeOriginal(original);
            Path patched = dir.resolve("patched.apk");
            List<ApkOverlapper.NewEntry> entries = List.of(
                    new ApkOverlapper.NewEntry("AndroidManifest.xml", bytes("new manifest")),
                    new ApkOverlapper.NewEntry("classes2.dex", bytes("new dex")));

            long originSize = ApkOverlapper.write(original.toFile(), patched.toFile(), entries);
            check(originSize == source.length, "origin size");

            File restored = OriginRestorer.restore(patched.toFile(), dir.toString());
            check(restored != null, "restored file");
            check(Arrays.equals(source, Files.readAllBytes(restored.toPath())),
                    "round-trip bytes");
        } finally {
            delete(dir);
        }
    }

    private static byte[] writeOriginal(Path file) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(buffer)) {
            zip.setComment("original zip comment");
            put(zip, "AndroidManifest.xml", bytes("old manifest"));
            put(zip, "classes.dex", bytes("old dex"));
            put(zip, "assets/data.bin", bytes("data"));
            put(zip, "META-INF/MANIFEST.MF", bytes("Manifest-Version: 1.0\n"));
            put(zip, "META-INF/CERT.SF", bytes("Signature-Version: 1.0\n"));
            put(zip, "META-INF/CERT.RSA", bytes("signature"));
        }
        byte[] data = buffer.toByteArray();
        Files.write(file, data);
        return data;
    }

    private static void put(ZipOutputStream zip, String name, byte[] data) throws IOException {
        ZipEntry entry = new ZipEntry(name);
        zip.putNextEntry(entry);
        zip.write(data);
        zip.closeEntry();
    }

    private static void testApkPath() {
        String packageName = "com.example";
        check(ApkPathMatcher.matches(packageName, "/data/app/com.example/base.apk"),
                "data/app exact");
        check(ApkPathMatcher.matches(packageName,
                        "/data/app/~~hash==/com.example-abc==/base.apk"),
                "data/app hashed");
        check(ApkPathMatcher.matches(packageName, "/mnt/asec/com.example/pkg.apk"),
                "asec");
        check(ApkPathMatcher.matches(packageName,
                        "/mnt/expand/uuid/app/com.example/base.apk"),
                "expand");

        check(!ApkPathMatcher.matches(packageName, "/data/app/com.example.evil/base.apk"),
                "package prefix");
        check(!ApkPathMatcher.matches(packageName,
                        "/data/app/~~hash==/com.example.evil==/base.apk"),
                "hashed package prefix");
        check(!ApkPathMatcher.matches(packageName,
                        "/mnt/expand/uuid/app/evilcom.example/base.apk"),
                "package suffix");
        check(!ApkPathMatcher.matches(packageName, "/data/app/com.example2/base.apk"),
                "longer package name");
        check(!ApkPathMatcher.matches(packageName, "/data/app/com.example/base.zip"),
                "not an apk");
        check(!ApkPathMatcher.matches(null, "/data/app/com.example/base.apk"),
                "missing package");
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    private static void delete(Path dir) throws IOException {
        try (Stream<Path> paths = Files.walk(dir)) {
            paths.sorted(Comparator.reverseOrder()).forEach(path -> path.toFile().delete());
        }
    }
}
