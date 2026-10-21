package alienkrishn.qrylz.payload;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.Signature;
import android.util.Base64;
import android.util.Log;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;

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

    private static volatile boolean installed;

    private QrylzPayload() {
    }

    /**
     * Installs the signature proxy. Safe to call more than once and never throws: a
     * failure here must not take the host application down with it.
     *
     * @param context any context of the host application
     */
    public static void install(Context context) {
        if (installed) {
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
                Log.w(TAG, "Signature proxy not installed (hidden API access denied?)");
            }
        } catch (Throwable t) {
            Log.w(TAG, "Signature proxy setup failed", t);
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
     * Swaps {@code ActivityThread.mPackageManager} for a proxy that rewrites the
     * signature of the package we are running in.
     */
    private static boolean installProxy(Signature original) {
        try {
            Class<?> threadClass = Class.forName("android.app.ActivityThread");
            Method current = threadClass.getMethod("currentActivityThread");
            Object activityThread = current.invoke(null);
            if (activityThread == null) {
                return false;
            }

            Field field = threadClass.getDeclaredField("mPackageManager");
            field.setAccessible(true);
            Object manager = field.get(activityThread);
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
            field.set(activityThread, proxy);
            return true;
        } catch (Throwable t) {
            Log.w(TAG, "Cannot reach ActivityThread.mPackageManager", t);
            return false;
        }
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
            if ("getPackageInfo".equals(method.getName()) && result instanceof PackageInfo) {
                PackageInfo info = (PackageInfo) result;
                info.signatures = new Signature[]{original};
            }
            return result;
        }
    }
}
