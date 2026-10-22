package alienkrishn.qrylz;

import com.reandroid.apk.ApkModule;
import com.reandroid.arsc.chunk.xml.AndroidManifestBlock;
import com.reandroid.arsc.chunk.xml.ResXmlAttribute;
import com.reandroid.arsc.chunk.xml.ResXmlElement;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Reads and writes the binary AndroidManifest.xml of an apk.
 * <p>
 * The manifest stays in its binary form, the way the apk stores it. It is patched
 * through ARSCLib and written back by ARSCLib as well: writing a detached block loses
 * the resource table it needs and produces a manifest the platform refuses to parse.
 */
public final class ManifestEditor {

    /** Resource id of the android attribute {@code appComponentFactory}. */
    private static final int ID_APP_COMPONENT_FACTORY = 0x0101055a;

    private ManifestEditor() {
    }

    /**
     * Points {@code android:appComponentFactory} at the given class.
     * <p>
     * The factory is the earliest point where the payload can run: the system asks it
     * for the application instance before the application class is loaded. The factory
     * that was in the manifest before is returned so that it can still be used for the
     * actual instantiation.
     *
     * @param apk     the apk that carries the manifest
     * @param factory the class to use
     * @return the patched manifest and the factory that was there before
     * @throws IOException when the manifest cannot be read or written
     */
    public static Result setAppComponentFactory(File apk, String factory) throws IOException {
        File temporary = File.createTempFile("qrylz-manifest", ".apk");
        temporary.deleteOnExit();
        String previous = null;
        try (ApkModule module = ApkModule.loadApkFile(apk)) {
            AndroidManifestBlock manifest = module.getAndroidManifest();
            ResXmlElement application = manifest.getOrCreateApplicationElement();
            for (Iterator<ResXmlAttribute> it = application.getAttributes(); it.hasNext(); ) {
                ResXmlAttribute attribute = it.next();
                if ("appComponentFactory".equals(attribute.getName())) {
                    previous = attribute.getValueString();
                    attribute.setValueAsString(factory);
                    break;
                }
            }
            if (previous == null) {
                ResXmlAttribute attribute = application.getOrCreateAndroidAttribute(
                        "appComponentFactory", ID_APP_COMPONENT_FACTORY);
                attribute.setValueAsString(factory);
            }
            module.writeApk(temporary);
        }
        try {
            byte[] bytes = readEntry(temporary, "AndroidManifest.xml");
            return new Result(bytes, previous);
        } finally {
            temporary.delete();
        }
    }

    /**
     * The patched manifest and the factory that was in it before.
     */
    public static final class Result {
        private final byte[] manifest;
        private final String previousFactory;

        Result(byte[] manifest, String previousFactory) {
            this.manifest = manifest;
            this.previousFactory = previousFactory;
        }

        public byte[] getManifest() {
            return manifest;
        }

        /** @return the factory that was in the manifest before, empty when there was none */
        public String getPreviousFactory() {
            return previousFactory == null ? "" : previousFactory;
        }
    }

    /**
     * @return the raw bytes of an entry of an apk
     */
    static byte[] readEntry(File apk, String name) throws IOException {
        try (ZipFile zip = new ZipFile(apk)) {
            ZipEntry entry = zip.getEntry(name);
            if (entry == null) {
                throw new IOException("No " + name + " in " + apk);
            }
            try (InputStream in = zip.getInputStream(entry)) {
                java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
                byte[] buffer = new byte[65536];
                int read;
                while ((read = in.read(buffer)) != -1) {
                    out.write(buffer, 0, read);
                }
                return out.toByteArray();
            }
        }
    }
}
