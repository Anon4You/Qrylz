package alienkrishn.qrylz.payload;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.util.Base64;
import android.util.Log;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.Proxy;
import java.util.Arrays;

/**
 * Runtime half of Qrylz.
 * <p>
 * This class is compiled into {@code payload.dex}, injected into the target APK and
 * started from the target Application's {@code attachBaseContext}. It replaces the
 * {@code IPackageManager} instance held by {@code ActivityThread} with a dynamic proxy
 * that reports the <em>original</em> signing certificate instead of the certificate the
 * APK was re-signed with.
 * <p>
 * The certificate is embedded by the Qrylz CLI, which replaces the
 * {@link #SIGNATURE_BASE64} placeholder with the Base64 encoded DER of the certificate
 * taken from the untouched APK.
 * <p>
 * Accessing {@code ActivityThread.mPackageManager} is a hidden API call. On Android 9 and
 * newer that is rejected unless hidden API enforcement has been lifted, which is what the
 * accompanying native hook ({@code libqrylz_hook.so}) does before this class runs.
 */
public final class QrylzPayload {

    private static final String TAG = "Qrylz";

    /** Name of the native hook library, without the lib prefix and the .so suffix. */
    private static final String NATIVE_HOOK = "qrylz_hook";

    /**
     * Placeholder replaced by the Qrylz CLI with the Base64 encoded DER of the original
     * signing certificate. Kept as a constant so it lands in the dex string pool and can
     * be patched in place.
     */
    public static final String SIGNATURE_BASE64 = "PLACEHOLDER_SIG";

    /**
     * Placeholder for the app component factory that was in the manifest before the
     * patch. It is still used to instantiate the components of the application.
     */
    public static final String ORIGINAL_FACTORY = "PLACEHOLDER_FACTORY";

    private static volatile boolean installed;

    /** Package name of the host application, the only one whose signature is rewritten. */
    private static String hostPackage;

    private QrylzPayload() {
    }

    /**
     * Installs the signature proxy. Safe to call more than once and never throws: a
     * failure here must not take the host application down with it.
     *
     * @param context any context of the host application
     */
    public static void install(Context context) {
        if (context != null && hostPackage == null) {
            hostPackage = context.getPackageName();
        }
        installProxy();
    }

    /**
     * Installs the proxy without a context, used from the app component factory where
     * the package name is all that is available.
     *
     * @param packageName the package name of the host application, may be {@code null}
     */
    public static void installForPackage(String packageName) {
        if (packageName != null && !packageName.isEmpty() && hostPackage == null) {
            hostPackage = packageName;
        }
        installProxy();
    }

    private static void installProxy() {
        if (installed) {
            return;
        }
        if (hostPackage == null) {
            // Without the package name the proxy cannot tell its own package apart from
            // the others, so wait until the name is known.
            return;
        }
        installed = true;
        loadNativeHook();
        try {
            Signature original = originalSignature();
            if (original == null) {
                Log.w(TAG, "No original signature embedded, proxy not installed");
                return;
            }
            if (installProxy(original)) {
                Log.i(TAG, "Signature proxy installed");
            } else {
                Log.w(TAG, "Signature proxy not installed");
            }
        } catch (Throwable t) {
            Log.w(TAG, "Signature proxy setup failed", t);
        }
    }

    /**
     * Reads the signature back through the package manager and logs it, so it can be
     * checked against the certificate that was embedded at patch time.
     */
    private static void verify(Context context, Signature original) {
        try {
            PackageManager pm = context.getPackageManager();
            PackageInfo info = pm.getPackageInfo(context.getPackageName(), PackageManager.GET_SIGNATURES);
            Signature[] signatures = info.signatures;
            if (signatures == null || signatures.length == 0) {
                Log.w(TAG, "verify: no signature reported");
                return;
            }
            for (Signature signature : signatures) {
                boolean same = Arrays.equals(signature.toByteArray(), original.toByteArray());
                Log.i(TAG, "verify: signature sha256=" + sha256(signature.toByteArray())
                        + " matchesOriginal=" + same);
            }
        } catch (Throwable t) {
            Log.w(TAG, "verify failed", t);
        }
    }

    private static String sha256(byte[] data) {
        try {
            byte[] digest = java.security.MessageDigest.getInstance("SHA-256").digest(data);
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            return "error";
        }
    }

    /**
     * Loads the native hook.
     * <p>
     * The hook lifts the hidden API restriction on {@code ActivityThread} and serves the
     * original signature blocks to code that reads the APK file directly. Without it the
     * proxy cannot be installed on Android 9 and newer.
     */
    private static void loadNativeHook() {
        try {
            System.loadLibrary(NATIVE_HOOK);
            Log.i(TAG, "Native hook loaded");
        } catch (Throwable t) {
            Log.w(TAG, "Native hook " + NATIVE_HOOK + " not loaded", t);
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

    /**
     * Swaps the package manager of the process for a proxy that rewrites the signature
     * of package infos that belong to this process.
     * <p>
     * The field that holds the package manager moved between Android releases
     * ({@code ActivityThread.mPackageManager} became the static
     * {@code ActivityThread.sPackageManager}), so it is looked up by name first and by
     * type afterwards.
     */
    private static boolean installProxy(Signature original) {
        try {
            Class<?> threadClass = Class.forName("android.app.ActivityThread");
            Method current = threadClass.getMethod("currentActivityThread");
            Object activityThread = current.invoke(null);
            if (activityThread == null) {
                return false;
            }

            Field field = findPackageManagerField(threadClass);
            if (field == null) {
                Log.w(TAG, "No package manager field on ActivityThread");
                return false;
            }
            field.setAccessible(true);

            boolean isStatic = Modifier.isStatic(field.getModifiers());
            Object manager = isStatic ? field.get(null) : field.get(activityThread);
            if (manager == null || Proxy.isProxyClass(manager.getClass())) {
                return false;
            }

            Class<?>[] interfaces = manager.getClass().getInterfaces();
            if (interfaces.length == 0) {
                return false;
            }

            Object proxy = Proxy.newProxyInstance(
                    manager.getClass().getClassLoader(),
                    interfaces,
                    new SignatureHandler(manager, original));
            if (isStatic) {
                field.set(null, proxy);
            } else {
                field.set(activityThread, proxy);
            }
            Log.i(TAG, "Package manager field: " + field.getName() + " (static=" + isStatic + ")");
            return true;
        } catch (Throwable t) {
            Log.w(TAG, "Cannot reach the package manager of ActivityThread", t);
            return false;
        }
    }

    /**
     * Finds the field that holds the {@code IPackageManager} of the process.
     */
    private static Field findPackageManagerField(Class<?> threadClass) {
        for (String name : new String[]{"sPackageManager", "mPackageManager"}) {
            try {
                return threadClass.getDeclaredField(name);
            } catch (Throwable ignored) {
                // not present on this release, try the next one
            }
        }
        // Fall back to a type based lookup so the payload keeps working when the field
        // is renamed again.
        for (Field field : threadClass.getDeclaredFields()) {
            if ("android.content.pm.IPackageManager".equals(field.getType().getName())) {
                return field;
            }
        }
        return null;
    }

    /**
     * Forwards every call to the real package manager but rewrites the signature of
     * package infos that belong to this process.
     */
    private static final class SignatureHandler implements InvocationHandler {

        private final Object delegate;
        private final Signature original;

        SignatureHandler(Object delegate, Signature original) {
            this.delegate = delegate;
            this.original = original;
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            Object result = method.invoke(delegate, args);
            if (isHostPackage(args)) {
                Log.i(TAG, "pm call: " + method.getName() + " -> "
                        + (result == null ? "null" : result.getClass().getSimpleName()));
                if (result instanceof PackageInfo) {
                    PackageInfo info = (PackageInfo) result;
                    info.signatures = new Signature[]{original};
                    applySigningInfo(info, original);
                    applyApplicationInfoSignatures(info, original);
                }
            }
            return result;
        }

        /**
         * {@code ApplicationInfo} carries its own copy of the signatures. It is not part
         * of the public sdk any more, so it is reached by reflection.
         */
        private void applyApplicationInfoSignatures(PackageInfo info, Signature original) {
            try {
                Object applicationInfo = PackageInfo.class.getField("applicationInfo").get(info);
                if (applicationInfo == null) {
                    return;
                }
                java.lang.reflect.Field field =
                        applicationInfo.getClass().getField("signatures");
                field.set(applicationInfo, new Signature[]{original});
            } catch (Throwable ignored) {
                // Not present on this release.
            }
        }

        /**
         * Fills {@code PackageInfo.signingInfo} as well.
         * <p>
         * Since Android 9 the system hands the signing certificates over in
         * {@code signingInfo} and leaves the deprecated {@code signatures} array empty.
         * Which of the two an application reads is not visible from the outside, so both
         * are filled. {@code SigningInfo} does not exist before Android 9, therefore it
         * is reached by reflection.
         */
        private void applySigningInfo(PackageInfo info, Signature original) {
            try {
                Class<?> signingInfoClass = Class.forName("android.content.pm.SigningInfo");
                java.lang.reflect.Field field = PackageInfo.class.getField("signingInfo");
                Object existing = field.get(info);
                int scheme = 2;
                if (existing != null) {
                    scheme = (Integer) existing.getClass()
                            .getMethod("getSchemeVersion").invoke(existing);
                }
                java.util.Collection<Signature> one = java.util.Collections.singletonList(original);
                Object signingInfo = signingInfoClass
                        .getConstructor(int.class, java.util.Collection.class,
                                java.util.Collection.class, java.util.Collection.class)
                        .newInstance(scheme, one, java.util.Collections.emptyList(), one);
                field.set(info, signingInfo);
            } catch (Throwable ignored) {
                // Android 8 and older, or a different field layout - the deprecated
                // signatures array is enough there.
            }
        }

        /**
         * Methods that only take a uid cannot be attributed to a package name.
         */
        private boolean methodUsesUidOnly(Object[] args) {
            return !(args[0] instanceof String)
                    && !args[0].getClass().getName().contains("VersionedPackage");
        }

        /**
         * Only the host package may be rewritten. The package manager is asked about
         * other packages too - the WebView provider for example - and handing out our
         * certificate for those would break their own signature checks.
         */
        private boolean isHostPackage(Object[] args) {
            if (hostPackage == null || args == null || args.length == 0) {
                return false;
            }
            if (methodUsesUidOnly(args)) {
                return false;
            }
            Object first = args[0];
            if (first instanceof String) {
                return hostPackage.equals(first);
            }
            // android.pm.VersionedPackage
            try {
                Object name = first.getClass().getMethod("getPackageName").invoke(first);
                return hostPackage.equals(name);
            } catch (Throwable ignored) {
                return false;
            }
        }
    }
}
