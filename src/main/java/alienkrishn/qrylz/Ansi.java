package alienkrishn.qrylz;

/**
 * Colours for the output.
 * <p>
 * The escape sequences are only used when the output goes to a terminal, so that the log
 * of a run stays readable when it is piped into a file. The {@code NO_COLOR} environment
 * variable switches them off, as described by
 * <a href="https://no-color.org/">no-color.org</a>.
 */
final class Ansi {

    private static final boolean ENABLED = isEnabled();

    private Ansi() {
    }

    private static boolean isEnabled() {
        if (System.getenv("NO_COLOR") != null) {
            return false;
        }
        if ("1".equals(System.getenv("QRYLZ_COLOR"))) {
            return true;
        }
        return System.console() != null;
    }

    private static String wrap(String text, String code) {
        return ENABLED ? code + text + "[0m" : text;
    }

    static String bold(String text) {
        return wrap(text, "[1m");
    }

    static String dim(String text) {
        return wrap(text, "[2m");
    }

    static String cyan(String text) {
        return wrap(text, "[36m");
    }

    static String green(String text) {
        return wrap(text, "[32m");
    }

    static String yellow(String text) {
        return wrap(text, "[33m");
    }

    static String red(String text) {
        return wrap(text, "[31m");
    }

    static String blue(String text) {
        return wrap(text, "[34m");
    }
}
