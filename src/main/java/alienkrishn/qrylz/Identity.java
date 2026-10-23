package alienkrishn.qrylz;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * The identity printed by the tool.
 * <p>
 * The hash is checked before anything runs. Changing the author or the repository link
 * without updating it makes the tool refuse to start. This is a speed bump against
 * rebranding, not a cryptographic guarantee: the check lives in the same jar.
 */
final class Identity {

    static final String AUTHOR = "Alienkrishn";
    static final String HANDLE = "Anon4You";
    static final String REPO = "github.com/Anon4You/Qrylz";

    private static final String CHECK =
            "db9df846373749c17285f7a255192c3b4547a8e52b02918e4c740af0d29eee91";

    private Identity() {
    }

    static boolean valid() {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest((AUTHOR + "\n" + HANDLE + "\n" + REPO)
                    .getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(hash.length * 2);
            for (byte value : hash) {
                hex.append(Character.forDigit((value >> 4) & 0xF, 16));
                hex.append(Character.forDigit(value & 0xF, 16));
            }
            return CHECK.equals(hex.toString());
        } catch (Exception e) {
            return false;
        }
    }
}
