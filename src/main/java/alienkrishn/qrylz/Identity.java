package alienkrishn.qrylz;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

/**
 * The identity printed by the tool.
 * <p>
 * The values are stored encoded, and the digest is checked before the banner and the
 * pipeline run. Editing the encoded values without also replacing the digest makes the
 * tool refuse to run. This is tamper-evident, not tamper-proof: the check lives in the
 * same jar.
 */
final class Identity {

    private static final byte[] KEY =
            Base64.getDecoder().decode("aVYrNv2u/8v5XkkPpqTFPQ==");

    private static final String AUTHOR = decode("KDpCU5PFjaKKNic=");
    private static final String HANDLE = decode("KDhEWMn3kL4=");
    private static final String REPO = decode("Dj9fXojM0aiWM2ZOyMurCTA5Xhms3Iangw==");

    private static final byte[] CHECK =
            decodeBytes("ssvTcMqZtgqL276t873pBiwRg9PWrG5FtSpD/3Q6K6w=");

    private Identity() {
    }

    static String author() {
        ensureValid();
        return AUTHOR;
    }

    static String handle() {
        ensureValid();
        return HANDLE;
    }

    static String repo() {
        ensureValid();
        return REPO;
    }

    static boolean valid() {
        return check();
    }

    private static void ensureValid() {
        if (!check()) {
            throw new IllegalStateException("qrylz: this build has been modified");
        }
    }

    private static boolean check() {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest((AUTHOR + "\n" + HANDLE + "\n" + REPO)
                    .getBytes(StandardCharsets.UTF_8));
            return MessageDigest.isEqual(CHECK, hash);
        } catch (Exception e) {
            return false;
        }
    }

    private static String decode(String encoded) {
        return new String(decodeBytes(encoded), StandardCharsets.UTF_8);
    }

    private static byte[] decodeBytes(String encoded) {
        byte[] data = Base64.getDecoder().decode(encoded);
        for (int i = 0; i < data.length; i++) {
            data[i] ^= KEY[i % KEY.length];
        }
        return data;
    }
}
