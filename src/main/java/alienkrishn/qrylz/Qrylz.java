package alienkrishn.qrylz;

import com.android.tools.smali.dexlib2.DexFileFactory;
import com.android.tools.smali.dexlib2.iface.DexFile;
import com.android.tools.smali.dexlib2.iface.MultiDexContainer;
import com.reandroid.apk.ApkBundle;
import com.reandroid.apk.ApkModule;
import com.reandroid.archive.ByteInputSource;
import com.reandroid.archive.FileInputSource;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.util.Enumeration;
import java.util.Locale;
import java.util.concurrent.Callable;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Qrylz - patches an APK so that signature verification keeps working after the APK has
 * been re-signed.
 * <p>
 * The pipeline is:
 * <ol>
 *   <li>merge a split APK set into a single APK</li>
 *   <li>read the original signing certificate and the original {@code META-INF} folder</li>
 *   <li>pack the {@code META-INF} folder into {@code assets/qrylz_origin.zip}</li>
 *   <li>patch the signature placeholder inside the payload dex</li>
 *   <li>merge the payload into the application dex and hook the application class</li>
 *   <li>write the patched APK</li>
 * </ol>
 * The result is not signed. Sign it with your own key afterwards.
 */
@Command(
        name = "qrylz",
        mixinStandardHelpOptions = true,
        version = "qrylz 1.0.0",
        sortOptions = false,
        description = "Patches an APK so signature verification keeps working after re-signing."
)
public final class Qrylz implements Callable<Integer> {

    /** Application class used when the manifest does not declare one. */
    private static final String FALLBACK_APPLICATION = "alienkrishn.qrylz.payload.QrylzApplication";

    /** Native hook that is loaded from the patched application class. */
    private static final String NATIVE_HOOK = "qrylz_hook";

    @Option(names = {"-i", "--input"}, required = true, paramLabel = "<apk>",
            description = "Input APK or split APK set (.apk, .apks, .xapk, .apkm)")
    private File input;

    @Option(names = {"-o", "--output"}, required = true, paramLabel = "<apk>",
            description = "Output APK (not signed)")
    private File output;

    @Option(names = {"--payload"}, paramLabel = "<dex>",
            description = "Payload dex to inject. Defaults to the bundled payload.dex.")
    private File payload;

    @Option(names = {"--lib"}, paramLabel = "<so>",
            description = "Native hook to inject as lib/arm64-v8a/lib" + NATIVE_HOOK + ".so")
    private File nativeHook;

    @Override
    public Integer call() throws Exception {
        printBanner();

        File apk = resolveInput();
        log("input: " + apk);

        SignatureExtractor.SignatureData signature = SignatureExtractor.extract(apk);
        log("certificate: " + signature.getCertificateEntry()
                + "  sha256=" + signature.getSha256());

        byte[] originArchive = SignatureExtractor.buildOriginArchive(
                signature.getMetaInf(), signature.getCertificateDer());
        log("origin archive: " + SignatureExtractor.ORIGIN_ARCHIVE
                + " (" + originArchive.length + " bytes, " + signature.getMetaInf().size() + " entries)");

        DexFile payloadDex = DexInjector.loadPatchedPayload(readPayload(), signature.getBase64());
        log("payload: signature placeholder patched");

        try (ApkModule module = ApkModule.loadApkFile(apk)) {
            String applicationClass = module.getAndroidManifest().getApplicationClassName();
            if (applicationClass == null || applicationClass.isEmpty()) {
                applicationClass = FALLBACK_APPLICATION;
                module.getAndroidManifest().setApplicationClassName(applicationClass);
                log("manifest: no custom application class, using " + applicationClass);
            } else {
                log("application class: " + applicationClass);
            }

            MultiDexContainer<? extends DexFile> container = DexFileFactory.loadDexContainer(apk, null);
            String dexName = null;
            DexFile targetDex = null;
            for (String name : container.getDexEntryNames()) {
                MultiDexContainer.DexEntry<? extends DexFile> entry = container.getEntry(name);
                if (entry == null) {
                    continue;
                }
                DexFile candidate = entry.getDexFile();
                if (candidate != null && DexInjector.containsClass(candidate, applicationClass)) {
                    dexName = name;
                    targetDex = candidate;
                    break;
                }
            }
            if (targetDex == null) {
                throw new IOException("Application class " + applicationClass + " not found in any dex");
            }
            log("target dex: " + dexName);

            DexFile merged = DexInjector.merge(targetDex, payloadDex);
            boolean existing = DexInjector.hasAttachBaseContext(merged, applicationClass);
            DexFile hooked = DexInjector.injectApplicationHook(
                    merged, applicationClass, DexInjector.PAYLOAD_CLASS);
            log("hook: " + (existing
                    ? "patched attachBaseContext of " + applicationClass
                    : "created attachBaseContext in " + applicationClass));

            File patchedDex = File.createTempFile("qrylz-", ".dex");
            patchedDex.deleteOnExit();
            DexInjector.writeDexFile(hooked, patchedDex);

            module.getZipEntryMap().remove(dexName);
            module.add(new FileInputSource(patchedDex, dexName));

            String originPath = "assets/" + SignatureExtractor.ORIGIN_ARCHIVE;
            module.getZipEntryMap().remove(originPath);
            module.add(new ByteInputSource(originArchive, originPath));

            if (nativeHook != null) {
                String libPath = "lib/arm64-v8a/lib" + NATIVE_HOOK + ".so";
                module.getZipEntryMap().remove(libPath);
                module.add(new FileInputSource(nativeHook, libPath));
                log("native hook: " + libPath);
            }

            // The old signature no longer matches the patched content. Drop it so the
            // result stays installable once it is signed with a fresh key. The original
            // blocks are preserved in assets/qrylz_origin.zip.
            module.getZipEntryMap().removeIf(source -> source.getName().startsWith("META-INF/"));
            module.setApkSignatureBlock(null);
            log("removed the stale signature, the output has to be signed again");

            File parent = output.getAbsoluteFile().getParentFile();
            if (parent != null) {
                Files.createDirectories(parent.toPath());
            }
            module.writeApk(output);
        }

        log("written: " + output.getAbsolutePath());
        log("done - sign the output APK with your own key before installing it");
        return 0;
    }

    /**
     * @return the APK to work on, merging a split set on the way
     */
    private File resolveInput() throws IOException {
        if (input.isDirectory()) {
            return mergeSplits(input);
        }
        String name = input.getName().toLowerCase(Locale.US);
        if (name.endsWith(".apks") || name.endsWith(".xapk") || name.endsWith(".apkm")) {
            File directory = Files.createTempDirectory("qrylz-split").toFile();
            directory.deleteOnExit();
            unzip(input, directory);
            return mergeSplits(directory);
        }
        return input;
    }

    /**
     * Merges the APKs of a split set into a single APK.
     * <p>
     * This is the same engine the APKEditor command line uses: {@code ApkBundle} reads
     * every module of the directory, merges the manifests and the resource tables and
     * hands back one {@code ApkModule}.
     */
    private File mergeSplits(File directory) throws IOException {
        File merged = File.createTempFile("qrylz-merged-", ".apk");
        merged.deleteOnExit();

        try (ApkBundle bundle = new ApkBundle()) {
            bundle.loadApkDirectory(directory);
            try (ApkModule module = bundle.mergeModules()) {
                module.refreshTable();
                module.refreshManifest();
                module.writeApk(merged);
            }
        }

        log("merged " + directory.getName() + " -> " + merged.getName()
                + " (" + merged.length() + " bytes)");
        return merged;
    }

    /**
     * @return the payload dex, either the one given on the command line or the bundled one
     */
    private byte[] readPayload() throws IOException {
        if (payload != null) {
            return Files.readAllBytes(payload.toPath());
        }
        try (InputStream in = Qrylz.class.getClassLoader().getResourceAsStream("payload.dex")) {
            if (in == null) {
                throw new IOException("No payload.dex bundled and no --payload given");
            }
            return in.readAllBytes();
        }
    }

    private static void unzip(File archive, File target) throws IOException {
        try (ZipFile zip = new ZipFile(archive)) {
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                File destination = new File(target, entry.getName());
                if (!destination.getCanonicalPath().startsWith(target.getCanonicalPath())) {
                    throw new IOException("Refusing to extract outside the target directory: "
                            + entry.getName());
                }
                if (entry.isDirectory()) {
                    Files.createDirectories(destination.toPath());
                    continue;
                }
                Files.createDirectories(destination.toPath().getParent());
                try (InputStream in = zip.getInputStream(entry);
                     OutputStream out = Files.newOutputStream(destination.toPath())) {
                    in.transferTo(out);
                }
            }
        }
    }

    private static void printBanner() {
        System.out.println();
        System.out.println("============================================================");
        System.out.println(" Qrylz 1.0.0 - signature verification test harness");
        System.out.println();
        System.out.println(" This tool is meant for APKs you own or are authorised to");
        System.out.println(" test. It bypasses signature verification so that a re-signed");
        System.out.println(" build keeps working. Running it against third party apps");
        System.out.println(" breaks their licence checks and is not the intended use.");
        System.out.println("============================================================");
        System.out.println();
    }

    private static void log(String message) {
        System.out.println("[qrylz] " + message);
    }

    public static void main(String[] args) {
        System.exit(new CommandLine(new Qrylz()).execute(args));
    }
}
