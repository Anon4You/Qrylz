package alienkrishn.qrylz;

import com.android.tools.smali.dexlib2.DexFileFactory;
import com.android.tools.smali.dexlib2.iface.DexFile;
import com.android.tools.smali.dexlib2.iface.MultiDexContainer;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
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
 *   <li>read the original signing certificate</li>
 *   <li>patch the manifest so the payload starts before the application class</li>
 *   <li>patch the signature placeholder inside the payload dex</li>
 *   <li>write the original apk as a prefix and append the payload</li>
 * </ol>
 * The original apk stays inside the new one, byte for byte, so the payload can serve it
 * to a check that reads the certificate out of the apk file. The result is not signed, it
 * has to be signed with a key afterwards.
 */
@Command(
        name = "qrylz",
        mixinStandardHelpOptions = true,
        versionProvider = Qrylz.Version.class,
        sortOptions = false,
        description = "Patches an APK so signature verification keeps working after re-signing."
)
public final class Qrylz implements Callable<Integer> {

    /** Factory that installs the payload before the application class is loaded. */
    private static final String APP_COMPONENT_FACTORY =
            "alienkrishn.qrylz.payload.QrylzAppComponentFactory";

    /** Native hook that redirects the opens of the apk. */
    private static final String NATIVE_HOOK = "qrylz_hook";

    @Option(names = {"-i", "--input"}, required = true, paramLabel = "<apk>",
            description = "Input APK or split APK set (.apk, .apks, .xapk, .apkm)")
    private File input;

    @Option(names = {"-o", "--output"}, paramLabel = "<apk>",
            description = "Output APK (not signed). Defaults to <input>_qrylz.apk next to the input.")
    private File output;

    @Option(names = {"--payload"}, paramLabel = "<dex>",
            description = "Payload dex to inject. Defaults to the bundled payload.dex.")
    private File payload;

    @Option(names = {"--lib"}, paramLabel = "<so>",
            description = "Native hook to inject as lib/arm64-v8a/lib" + NATIVE_HOOK
                    + ".so. Defaults to the one bundled in this jar.")
    private File nativeHook;

    @Override
    public Integer call() throws Exception {
        printBanner();

        File apk = resolveInput();
        log("input: " + apk);

        SignatureExtractor.SignatureData signature = SignatureExtractor.extract(apk);
        log("certificate: " + signature.getCertificateEntry()
                + "  sha256=" + Ansi.green(signature.getSha256()));

        // The original apk becomes the prefix of the new one.
        long originSize = apk.length();

        // The manifest points at the payload factory, the application class stays as it is.
        ManifestEditor.Result manifest = ManifestEditor.setAppComponentFactory(
                apk, APP_COMPONENT_FACTORY);
        log("manifest: appComponentFactory -> " + Ansi.yellow(APP_COMPONENT_FACTORY)
                + (manifest.getPreviousFactory().isEmpty()
                ? "" : " (was " + manifest.getPreviousFactory() + ")"));

        // The payload carries the original certificate and the size of the original apk.
        Map<String, String> placeholders = new LinkedHashMap<>();
        placeholders.put(DexInjector.PLACEHOLDER, signature.getBase64());
        placeholders.put(DexInjector.FACTORY_PLACEHOLDER, manifest.getPreviousFactory());
        placeholders.put(DexInjector.ORIGIN_SIZE_PLACEHOLDER, String.valueOf(originSize));
        DexFile payloadDex = DexInjector.loadPatchedPayload(readPayload(), placeholders);
        log("payload: placeholders patched");

        String dexName = freeDexName(apk);
        List<ApkOverlapper.NewEntry> entries = new ArrayList<>();
        entries.add(new ApkOverlapper.NewEntry("AndroidManifest.xml", manifest.getManifest()));
        entries.add(new ApkOverlapper.NewEntry(dexName, toBytes(payloadDex)));
        byte[] hook = readNativeHook();
        entries.add(new ApkOverlapper.NewEntry(
                "lib/arm64-v8a/lib" + NATIVE_HOOK + ".so", hook));
        log("native hook: lib/arm64-v8a/lib" + NATIVE_HOOK + ".so"
                + " (" + hook.length + " bytes)");

        File target = output != null ? output : defaultOutput(input);
        File parent = target.getAbsoluteFile().getParentFile();
        if (parent != null) {
            Files.createDirectories(parent.toPath());
        }
        long written = ApkOverlapper.write(apk, target, entries);
        log("written: " + Ansi.green(target.getAbsolutePath())
                + " (" + target.length() + " bytes, origin " + written + " bytes)");

        log("done - sign the output APK with your own key before installing it");
        return 0;
    }

    /**
     * @return the file the patched apk is written to when no output was given
     */
    private static File defaultOutput(File input) {
        String name = input.getName();
        int dot = name.lastIndexOf('.');
        if (dot > 0) {
            name = name.substring(0, dot);
        }
        File parent = input.getAbsoluteFile().getParentFile();
        return new File(parent, name + "_qrylz.apk");
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
     * This is the engine the APKEditor command line uses: {@code ApkBundle} reads every
     * module of the directory, merges the manifests and the resource tables and hands
     * back one {@code ApkModule}.
     */
    private File mergeSplits(File directory) throws IOException {
        File merged = File.createTempFile("qrylz-merged-", ".apk");
        merged.deleteOnExit();

        try (com.reandroid.apk.ApkBundle bundle = new com.reandroid.apk.ApkBundle()) {
            bundle.loadApkDirectory(directory);
            try (com.reandroid.apk.ApkModule module = bundle.mergeModules()) {
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
     * @return the native hook, either the one given on the command line or the bundled one
     */
    private byte[] readNativeHook() throws IOException {
        if (nativeHook != null) {
            return Files.readAllBytes(nativeHook.toPath());
        }
        try (InputStream in = Qrylz.class.getClassLoader()
                .getResourceAsStream("native/arm64-v8a/lib" + NATIVE_HOOK + ".so")) {
            if (in == null) {
                throw new IOException("No native hook bundled and no --lib given");
            }
            return in.readAllBytes();
        }
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

    /**
     * @return a dex name that is not used by the apk yet
     */
    private String freeDexName(File apk) throws IOException {
        List<String> used = new ArrayList<>();
        try (ZipFile zip = new ZipFile(apk)) {
            for (Enumeration<? extends ZipEntry> it = zip.entries(); it.hasMoreElements(); ) {
                String name = it.nextElement().getName();
                if (name.startsWith("classes") && name.endsWith(".dex")) {
                    used.add(name);
                }
            }
        }
        for (int i = 2; i < 100; i++) {
            String name = "classes" + i + ".dex";
            if (!used.contains(name)) {
                return name;
            }
        }
        throw new IOException("No free dex name left");
    }

    /**
     * @return the raw bytes of an entry of the apk
     */
    private static byte[] readEntry(File apk, String name) throws IOException {
        try (ZipFile zip = new ZipFile(apk)) {
            ZipEntry entry = zip.getEntry(name);
            if (entry == null) {
                throw new IOException("No " + name + " in " + apk);
            }
            try (InputStream in = zip.getInputStream(entry)) {
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                byte[] buffer = new byte[65536];
                int read;
                while ((read = in.read(buffer)) != -1) {
                    out.write(buffer, 0, read);
                }
                return out.toByteArray();
            }
        }
    }

    /**
     * @return the dex written to bytes
     */
    private static byte[] toBytes(DexFile dex) throws IOException {
        File temporary = File.createTempFile("qrylz-payload", ".dex");
        temporary.deleteOnExit();
        DexFileFactory.writeDexFile(temporary.getAbsolutePath(), dex);
        byte[] data = Files.readAllBytes(temporary.toPath());
        temporary.delete();
        return data;
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

    private static final String[] LOGO = {
            " ███  ████  █   █ █     █   █ █████",
            "█   █ █   █  █ █  █      █ █     █",
            "█ █ █ ████    █   █       █     █",
            "█  █  █  █    █   █       █    █",
            " ██ █ █   █   █   █████   █   █████",
    };

    /** What is printed on the right side of the logo. */
    private static final String[][] SIDEBAR = {
            {Ansi.dim("1.0.0"), " ", Ansi.cyan("signature verification test harness")},
            {Ansi.yellow("Alienkrishn"), " ", Ansi.dim("[Anon4You]")},
            {Ansi.dim("github.com/Anon4You/Qrylz")},
    };

    private static void printBanner() {
        System.out.println();
        for (int i = 0; i < LOGO.length; i++) {
            StringBuilder line = new StringBuilder(Ansi.cyan(LOGO[i]));
            if (i < SIDEBAR.length) {
                line.append("  ");
                for (String part : SIDEBAR[i]) {
                    line.append(part);
                }
            }
            System.out.println(line);
        }
        System.out.println();
        System.out.println(" " + Ansi.yellow("This tool is meant for APKs you own or are authorised to"));
        System.out.println(" " + Ansi.yellow("test. It bypasses signature verification so that a re-signed"));
        System.out.println(" " + Ansi.yellow("build keeps working. Running it against third party apps"));
        System.out.println(" " + Ansi.yellow("breaks their licence checks and is not the intended use."));
        System.out.println();
    }

    private static void log(String message) {
        System.out.println(Ansi.cyan("[qrylz]") + " " + message);
    }

    /**
     * The version banner of the tool.
     */
    static final class Version implements CommandLine.IVersionProvider {
        @Override
        public String[] getVersion() {
            return new String[]{
                    "qrylz 1.0.0",
                    "signature verification test harness",
                    "Alienkrishn [Anon4You]",
                    "https://github.com/Anon4You/Qrylz",
            };
        }
    }

    public static void main(String[] args) {
        System.exit(new CommandLine(new Qrylz()).execute(args));
    }
}
