package alienkrishn.qrylz.payload;

import android.util.Log;

/**
 * Bridge to the native hook.
 * <p>
 * The library is loaded on demand, so the payload still works when the hook was not
 * injected.
 */
public final class QrylzNative {

    private static boolean loaded;

    private QrylzNative() {
    }

    /**
     * Loads the native hook and tells it which file to serve instead of the APK of the
     * host application.
     *
     * @param apkPath   path of the APK of the host application
     * @param originPath path of the original APK
     * @return {@code true} when the hook was installed
     */
    public static synchronized boolean init(String apkPath, String originPath) {
        if (loaded) {
            return true;
        }
        try {
            System.loadLibrary("qrylz_hook");
            loaded = true;
        } catch (Throwable t) {
            Log.w("Qrylz", "Native hook not available", t);
            return false;
        }
        try {
            nativeInit(apkPath, originPath);
            return true;
        } catch (Throwable t) {
            Log.w("Qrylz", "Native hook setup failed", t);
            return false;
        }
    }

    /**
     * @param apkPath    path of the APK of the host application
     * @param originPath path of the original APK
     */
    private static native void nativeInit(String apkPath, String originPath);
}
