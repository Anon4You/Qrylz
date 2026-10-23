package alienkrishn.qrylz.payload;

final class ApkPathMatcher {

    private ApkPathMatcher() {
    }

    static boolean matches(String packageName, String path) {
        if (packageName == null || packageName.isEmpty()
                || path == null || !path.startsWith("/") || !path.endsWith(".apk")) {
            return false;
        }
        String[] parts = path.substring(1).split("/", 6);
        int count = parts.length;
        if (count == 4 || count == 5) {
            if (parts[0].equals("data") && parts[1].equals("app")
                    && parts[count - 1].equals("base.apk")) {
                return packageDir(parts[count - 2], packageName);
            }
            if (parts[0].equals("mnt") && parts[1].equals("asec")
                    && parts[count - 1].equals("pkg.apk")) {
                return packageDir(parts[count - 2], packageName);
            }
        } else if (count == 3) {
            if (parts[0].equals("data") && parts[1].equals("app")) {
                return packageDir(parts[2], packageName);
            }
        } else if (count == 6) {
            if (parts[0].equals("mnt") && parts[1].equals("expand") && parts[3].equals("app")
                    && parts[5].equals("base.apk")) {
                return packageDir(parts[4], packageName);
            }
        }
        return false;
    }

    private static boolean packageDir(String dir, String packageName) {
        return dir.equals(packageName) || dir.startsWith(packageName + "-");
    }
}
