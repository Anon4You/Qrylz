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
import java.nio.file.Path;
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

    /**
     * The abis the native hook is built for.
     * <p>
     * The hook may only go into a directory the apk already has. Adding a directory for
     * an abi the apk does not support would make the package manager refuse to install
     * it on a device of that abi.
     */
    private static final String[] HOOK_ABIS = {"arm64-v8a", "armeabi-v7a", "x86_64", "x86"};

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
            description = "Native hook to inject as lib/<abi>/lib" + NATIVE_HOOK
                    + ".so. Defaults to the one bundled in this jar.")
    private File nativeHook;

    @Override
    public Integer call() throws Exception {
        if (!Identity.valid()) {
            System.err.println("qrylz: this build has been modified, refusing to run");
            return 1;
        }
        if (!input.exists()) {
            System.err.println("qrylz: input does not exist: " + input.getAbsolutePath());
            return 2;
        }
        File apk = resolveInput();
        log("input: " + apk);

        // The native hook may only go into a directory the apk already has, and every
        // abi of the apk needs the build of its own instruction set.
        List<String> abis = abis(apk);
        List<String> hooked = new ArrayList<>();
        for (String abi : abis) {
            if (hasHook(abi)) {
                hooked.add(abi);
            } else {
                log("native hook: no build for " + abi);
            }
        }
        if (hooked.isEmpty()) {
            log("native hook: the apk has no library of a known abi, only the java level"
                    + " bypass is applied");
        } else {
            log("native hook: " + String.join(", ", hooked));
        }

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
        for (String abi : hooked) {
            entries.add(new ApkOverlapper.NewEntry(
                    "lib/" + abi + "/lib" + NATIVE_HOOK + ".so", readNativeHook(abi)));
        }

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
     * @return the version of the build
     */
    private static String readVersion() {
        try (InputStream in = Qrylz.class.getClassLoader()
                .getResourceAsStream("qrylz-version.txt")) {
            if (in != null) {
                String version = new String(in.readAllBytes(),
                        java.nio.charset.StandardCharsets.UTF_8).trim();
                if (!version.isEmpty()) {
                    return version;
                }
            }
        } catch (Exception ignored) {
        }
        return "0.0.0";
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
     * @return the abis the apk carries native libraries for
     */
    private static List<String> abis(File apk) throws IOException {
        List<String> present = new ArrayList<>();
        try (ZipFile zip = new ZipFile(apk)) {
            for (Enumeration<? extends ZipEntry> it = zip.entries(); it.hasMoreElements(); ) {
                String name = it.nextElement().getName();
                if (!name.startsWith("lib/")) {
                    continue;
                }
                int slash = name.indexOf('/', 4);
                if (slash > 4) {
                    String abi = name.substring(4, slash);
                    if (!present.contains(abi)) {
                        present.add(abi);
                    }
                }
            }
        }
        return present;
    }

    /**
     * @return true when a build of the native hook exists for the abi
     */
    private boolean hasHook(String abi) {
        if (nativeHook != null) {
            // A hook given on the command line is used for every abi.
            return true;
        }
        return Qrylz.class.getClassLoader()
                .getResource("native/" + abi + "/lib" + NATIVE_HOOK + ".so") != null;
    }

    /**
     * @return the native hook for an abi, either the one given on the command line or the
     *         bundled one
     */
    private byte[] readNativeHook(String abi) throws IOException {
        if (nativeHook != null) {
            return Files.readAllBytes(nativeHook.toPath());
        }
        try (InputStream in = Qrylz.class.getClassLoader()
                .getResourceAsStream("native/" + abi + "/lib" + NATIVE_HOOK + ".so")) {
            if (in == null) {
                throw new IOException("No native hook bundled for " + abi);
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
        Path root = target.toPath().toAbsolutePath().normalize();
        try (ZipFile zip = new ZipFile(archive)) {
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                Path destination = root.resolve(entry.getName()).normalize();
                if (!destination.startsWith(root)) {
                    throw new IOException("Refusing to extract outside the target directory: "
                            + entry.getName());
                }
                if (entry.isDirectory()) {
                    Files.createDirectories(destination);
                    continue;
                }
                Files.createDirectories(destination.getParent());
                try (InputStream in = zip.getInputStream(entry);
                     OutputStream out = Files.newOutputStream(destination)) {
                    in.transferTo(out);
                }
            }
        }
    }

    private static final String[] LOGO = {
            " ███  ████  █   █ █     █████",
            "█   █ █   █  █ █  █        █",
            "█ █ █ ████    █   █       █",
            "█  █  █  █    █   █      █",
            " ██ █ █   █   █   █████ █████",
    };

    /** The version of the build, read from the resource the build generates. */
    private static final String VERSION = readVersion();

    private static void printBanner() {
        String[][] sidebar = {
                {Ansi.dim(VERSION)},
                {Ansi.yellow(Identity.author()), " ", Ansi.dim("[" + Identity.handle() + "]")},
                {Ansi.dim(Identity.repo())},
        };
        System.out.println();
        for (int i = 0; i < LOGO.length; i++) {
            StringBuilder line = new StringBuilder(Ansi.cyan(LOGO[i]));
            if (i < sidebar.length) {
                line.append("  ");
                for (String part : sidebar[i]) {
                    line.append(part);
                }
            }
            System.out.println(line);
        }
        System.out.println();
        System.out.println(" " + Ansi.cyan("signature verification test harness"));
        System.out.println(" " + Ansi.dim("For APKs you own or are authorised to test."));
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
                    "qrylz " + VERSION,
                    "signature verification test harness",
                    Identity.author() + " [" + Identity.handle() + "]",
                    "https://" + Identity.repo(),
            };
        }
    }

    public static void main(String[] args) {
        if (!Identity.valid()) {
            System.err.println("qrylz: this build has been modified, refusing to run");
            System.exit(1);
        }
        // The banner is printed before the command line is parsed, so that it shows up
        // for every invocation, including --help and --version.
        printBanner();
        System.exit(new CommandLine(new Qrylz()).execute(args));
    }
}
