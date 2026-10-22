package alienkrishn.qrylz.payload;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.Signature;
import android.os.Build;
import android.os.Parcel;
import android.os.Parcelable;
import android.util.Base64;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Runtime half of Qrylz.
 * <p>
 * Two things are needed to keep signature verification working after the apk was
 * re-signed:
 * <ul>
 *   <li>the java level check - every {@link PackageInfo} that is unmarshalled from a
 *       binder has to report the original certificate. That is done by replacing the
 *       parcel creator of {@link PackageInfo}, which covers every code path that asks
 *       the package manager for the signature.</li>
 *   <li>the native level check - code that reads the certificate out of the apk file
 *       itself. The apk is opened through the libc, so a small native library redirects
 *       the opens of the apk to a copy of the original apk.</li>
 * </ul>
 */
public final class QrylzPayload {

    private static final String TAG = "Qrylz";

    /**
     * Replaced by the Qrylz CLI with the Base64 of the original signing certificate.
     */
    public static final String SIGNATURE_BASE64 = "PLACEHOLDER_SIG";

    /**
     * Replaced by the Qrylz CLI with the name of the factory that was in the manifest
     * before the patch.
     */
    public static final String ORIGINAL_FACTORY = "PLACEHOLDER_FACTORY";

    /**
     * Replaced by the Qrylz CLI with the size of the original apk inside the patched
     * one. The first bytes of the patched apk are the original apk, byte for byte.
     */
    public static final String ORIGIN_SIZE = "PLACEHOLDER_ORIGIN_SIZE";

    /** Entry the original apk is read from. */
    private static final String ORIGIN_ASSET = "qrylz_origin.apk";

    private static volatile boolean installed;

    private QrylzPayload() {
    }

    /**
     * Starts the payload.
     *
     * @param packageName package name of the host application
     * @param apkPath     path of the apk of the host application
     */
    public static synchronized void install(String packageName, String apkPath) {
        if (installed) {
            return;
        }
        installed = true;
        try {
            killPackageInfo(packageName);
        } catch (Throwable t) {
            Log.w(TAG, "Cannot patch the package info", t);
        }
        try {
            killOpen(packageName, apkPath);
        } catch (Throwable t) {
            Log.w(TAG, "Cannot hook the apk path", t);
        }
    }

    /**
     * Starts the payload with a context, used when the application class was patched.
     *
     * @param context context of the host application
     */
    public static synchronized void install(Context context) {
        if (context == null) {
            return;
        }
        String packageName = context.getPackageName();
        String apkPath = getApkPath(packageName);
        if (apkPath == null) {
            apkPath = context.getApplicationInfo() == null
                    ? null : context.getApplicationInfo().sourceDir;
        }
        install(packageName, apkPath);
    }

    // ------------------------------------------------------------------ java level

    /**
     * Replaces the parcel creator of {@link PackageInfo}, so that every package info
     * that is unmarshalled reports the original certificate.
     * <p>
     * This is the way that covers all callers: the package manager is asked in many
     * different ways and every answer is unmarshalled through the same creator.
     */
    private static void killPackageInfo(String packageName) throws Exception {
        final Signature original = originalSignature();
        if (original == null) {
            Log.w(TAG, "No original signature embedded");
            return;
        }

        Parcelable.Creator<PackageInfo> originalCreator = PackageInfo.CREATOR;
        Parcelable.Creator<PackageInfo> creator = new Parcelable.Creator<PackageInfo>() {
            @Override
            public PackageInfo createFromParcel(Parcel source) {
                PackageInfo info = originalCreator.createFromParcel(source);
                if (info != null && packageName.equals(info.packageName)) {
                    applyOriginal(info, original);
                }
                return info;
            }

            @Override
            public PackageInfo[] newArray(int size) {
                return originalCreator.newArray(size);
            }
        };

        try {
            Field field = findField(PackageInfo.class, "CREATOR");
            field.set(null, creator);
            Log.i(TAG, "package info creator patched");
        } catch (Throwable t) {
            // The field is final on some releases, then the parcel has to be patched
            // instead.
            Log.w(TAG, "Cannot replace the creator, patching the parcel caches", t);
            clearParcelCaches();
        }
        clearPackageInfoCache();
    }

    private static void applyOriginal(PackageInfo info, Signature original) {
        try {
            if (info.signatures != null && info.signatures.length > 0) {
                info.signatures[0] = original;
            } else {
                info.signatures = new Signature[]{original};
            }
        } catch (Throwable ignored) {
        }
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && info.signingInfo != null) {
                Signature[] signers = info.signingInfo.getApkContentsSigners();
                if (signers != null && signers.length > 0) {
                    signers[0] = original;
                }
            }
        } catch (Throwable ignored) {
        }
    }

    /**
     * @return the original signing certificate embedded by the CLI, or {@code null}
     */
    public static Signature originalSignature() {
        try {
            String encoded = SIGNATURE_BASE64;
            // The guard is a length check on purpose. The placeholder is a compile time
            // constant, so javac inlines it at every use site - a literal comparison
            // against the placeholder would be rewritten by the patcher as well and would
            // then always match.
            if (encoded == null || encoded.length() < 64) {
                return null;
            }
            byte[] der = Base64.decode(encoded, Base64.DEFAULT);
            return der.length == 0 ? null : new Signature(der);
        } catch (Throwable t) {
            Log.w(TAG, "Cannot decode embedded signature", t);
            return null;
        }
    }

    // ------------------------------------------------------------------ native level

    /**
     * Extracts the original apk and lets the native library serve it instead of the
     * patched one.
     */
    private static void killOpen(String packageName, String apkPath) throws IOException {
        if (apkPath == null) {
            Log.w(TAG, "No apk path");
            return;
        }
        File origin = extractOrigin(apkPath);
        if (origin == null) {
            Log.w(TAG, "No original apk found");
            return;
        }
        if (!QrylzNative.init(apkPath, origin.getAbsolutePath())) {
            return;
        }
        Log.i(TAG, "apk path hooked: " + apkPath + " -> " + origin.getAbsolutePath());
    }

    /**
     * Writes the original apk - the first bytes of the patched one - into the files
     * directory of the application.
     */
    private static File extractOrigin(String apkPath) throws IOException {
        long originSize = originSize();
        File target = new File(dataDir(), ORIGIN_ASSET);
        if (target.isFile() && target.length() == originSize) {
            return target;
        }
        File temporary = new File(dataDir(), ORIGIN_ASSET + ".part");
        try (InputStream in = new java.io.FileInputStream(apkPath);
             OutputStream out = new FileOutputStream(temporary)) {
            byte[] buffer = new byte[65536];
            long total = 0;
            while (total < originSize) {
                int read = in.read(buffer, 0, (int) Math.min(buffer.length, originSize - total));
                if (read <= 0) {
                    break;
                }
                out.write(buffer, 0, read);
                total += read;
            }
            if (total != originSize) {
                throw new IOException("The original apk is shorter than expected");
            }
        }
        if (!temporary.renameTo(target)) {
            return temporary;
        }
        Log.i(TAG, "original apk extracted (" + target.length() + " bytes)");
        return target;
    }

    /**
     * @return the size of the original apk inside the patched one
     */
    private static long originSize() {
        try {
            return Long.parseLong(ORIGIN_SIZE);
        } catch (Throwable t) {
            return 0;
        }
    }

    /**
     * Finds the apk of the application in the memory maps of the process.
     * <p>
     * The source directory of the application info is not always the path the native
     * code uses, the memory maps are.
     */
    static String getApkPath(String packageName) {
        try (BufferedReader reader = new BufferedReader(new FileReader("/proc/self/maps"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split("\\s+");
                String path = parts[parts.length - 1];
                if (isApkPath(packageName, path)) {
                    return path;
                }
            }
        } catch (Throwable ignored) {
        }
        return null;
    }

    private static boolean isApkPath(String packageName, String path) {
        if (!path.startsWith("/") || !path.endsWith(".apk")) {
            return false;
        }
        String[] parts = path.substring(1).split("/", 6);
        int count = parts.length;
        if (count == 4 || count == 5) {
            if (parts[0].equals("data") && parts[1].equals("app")
                    && parts[count - 1].equals("base.apk")) {
                return parts[count - 2].startsWith(packageName);
            }
            if (parts[0].equals("mnt") && parts[1].equals("asec")
                    && parts[count - 1].equals("pkg.apk")) {
                return parts[count - 2].startsWith(packageName);
            }
        } else if (count == 3) {
            if (parts[0].equals("data") && parts[1].equals("app")) {
                return parts[2].startsWith(packageName);
            }
        } else if (count == 6) {
            if (parts[0].equals("mnt") && parts[1].equals("expand") && parts[3].equals("app")
                    && parts[5].equals("base.apk")) {
                return parts[4].endsWith(packageName);
            }
        }
        return false;
    }

    // ------------------------------------------------------------------ helpers

    private static File dataDir() {
        return new File("/data/data/" + hostPackageName());
    }

    private static String hostPackageName() {
        try {
            Class<?> threadClass = Class.forName("android.app.ActivityThread");
            Object thread = threadClass.getMethod("currentActivityThread").invoke(null);
            Field field = findField(threadClass, "mBoundApplication");
            Object bound = field.get(thread);
            if (bound == null) {
                return "";
            }
            Object info = findField(bound.getClass(), "appInfo").get(bound);
            return info == null ? "" : (String) findField(info.getClass(), "packageName").get(info);
        } catch (Throwable t) {
            return "";
        }
    }

    private static void clearPackageInfoCache() {
        try {
            Class<?> pmClass = Class.forName("android.content.pm.PackageManager");
            Object cache = findField(pmClass, "sPackageInfoCache").get(null);
            cache.getClass().getMethod("clear").invoke(cache);
        } catch (Throwable ignored) {
        }
    }

    private static void clearParcelCaches() {
        for (String name : new String[]{"mCreators", "sPairedCreators"}) {
            try {
                Object map = findField(Parcel.class, name).get(null);
                if (map instanceof java.util.Map) {
                    ((java.util.Map<?, ?>) map).clear();
                }
            } catch (Throwable ignored) {
            }
        }
    }

    private static Field findField(Class<?> clazz, String fieldName) throws NoSuchFieldException {
        Class<?> current = clazz;
        while (current != null && !current.equals(Object.class)) {
            try {
                Field field = current.getDeclaredField(fieldName);
                field.setAccessible(true);
                return field;
            } catch (NoSuchFieldException ignored) {
                current = current.getSuperclass();
            }
        }
        throw new NoSuchFieldException(fieldName);
    }
}
