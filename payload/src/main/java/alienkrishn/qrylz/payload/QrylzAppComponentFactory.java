package alienkrishn.qrylz.payload;

import android.app.Activity;
import android.app.AppComponentFactory;
import android.app.Application;
import android.app.Service;
import android.content.BroadcastReceiver;
import android.content.ContentProvider;
import android.content.Intent;
import android.content.pm.ApplicationInfo;

/**
 * Hook point that runs before the application class is even loaded.
 * <p>
 * The system asks the {@link AppComponentFactory} for the application instance, so this
 * is the earliest point where the signature proxy can be installed. That matters: an
 * application that loads a native library in its static initialiser could otherwise
 * cache the real package manager before the proxy is in place, and a check done by that
 * library would never see the spoofed certificate.
 * <p>
 * The factory named in the manifest before the patch is kept in
 * {@link QrylzPayload#ORIGINAL_FACTORY} and is still used for the actual instantiation,
 * so an application that relies on its own factory - androidx for example - keeps
 * working.
 */
public class QrylzAppComponentFactory extends AppComponentFactory {

    @Override
    public ClassLoader instantiateClassLoader(ClassLoader cl, ApplicationInfo info) {
        if (info != null) {
            String apkPath = QrylzPayload.getApkPath(info.packageName);
            if (apkPath == null) {
                apkPath = info.sourceDir;
            }
            QrylzPayload.install(info.packageName, apkPath, info.dataDir);
        }
        AppComponentFactory delegate = delegate();
        return delegate != null
                ? delegate.instantiateClassLoader(cl, info)
                : super.instantiateClassLoader(cl, info);
    }

    @Override
    public Application instantiateApplication(ClassLoader cl, String className)
            throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        AppComponentFactory delegate = delegate();
        return delegate != null
                ? delegate.instantiateApplication(cl, className)
                : super.instantiateApplication(cl, className);
    }

    @Override
    public Activity instantiateActivity(ClassLoader cl, String className, Intent intent)
            throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        AppComponentFactory delegate = delegate();
        return delegate != null
                ? delegate.instantiateActivity(cl, className, intent)
                : super.instantiateActivity(cl, className, intent);
    }

    @Override
    public BroadcastReceiver instantiateReceiver(ClassLoader cl, String className, Intent intent)
            throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        AppComponentFactory delegate = delegate();
        return delegate != null
                ? delegate.instantiateReceiver(cl, className, intent)
                : super.instantiateReceiver(cl, className, intent);
    }

    @Override
    public Service instantiateService(ClassLoader cl, String className, Intent intent)
            throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        AppComponentFactory delegate = delegate();
        return delegate != null
                ? delegate.instantiateService(cl, className, intent)
                : super.instantiateService(cl, className, intent);
    }

    @Override
    public ContentProvider instantiateProvider(ClassLoader cl, String className)
            throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        AppComponentFactory delegate = delegate();
        return delegate != null
                ? delegate.instantiateProvider(cl, className)
                : super.instantiateProvider(cl, className);
    }

    private static AppComponentFactory delegate;

    /**
     * @return the factory that was in the manifest before the patch, or {@code null} when
     *         there was none and the default implementation has to be used
     */
    private AppComponentFactory delegate() {
        if (delegate == null) {
            delegate = createDelegate();
        }
        return delegate;
    }

    private static AppComponentFactory createDelegate() {
        String name = QrylzPayload.ORIGINAL_FACTORY;
        if (name == null || name.isEmpty()) {
            return null;
        }
        try {
            Class<?> type = Class.forName(name, true, QrylzAppComponentFactory.class.getClassLoader());
            if (!AppComponentFactory.class.isAssignableFrom(type)
                    || type == QrylzAppComponentFactory.class) {
                return null;
            }
            return (AppComponentFactory) type.getDeclaredConstructor().newInstance();
        } catch (Throwable t) {
            return null;
        }
    }
}
