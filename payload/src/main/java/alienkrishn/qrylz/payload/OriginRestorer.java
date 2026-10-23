package alienkrishn.qrylz.payload;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.security.DigestOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Rebuilds the original apk from the installed one.
 * <p>
 * A signer that repacks the zip rewrites the first bytes of the file, but it keeps the
 * compressed data of the entries. The patched apk carries a template with the original
 * headers and the tail of the zip; the data of every entry is copied from the installed
 * apk, and the few entries that the signer changes are stored in the template. The
 * result is checked against the original size and sha-256.
 */
final class OriginRestorer {

    static final String TEMPLATE_ASSET = "assets/qrylz_origin.bin";

    private static final int TEMPLATE_MAGIC = 0x51524F54;
    private static final int TEMPLATE_VERSION = 1;
    private static final int MAX_ENTRIES = 1_000_000;

    private OriginRestorer() {
    }

    /**
     * @return the rebuilt original apk, or {@code null} when the apk has no template
     * @throws IOException when the template is invalid or the data does not rebuild it
     */
    static File restore(File apk, String dataDir) throws IOException {
        if (dataDir == null || dataDir.isEmpty()) {
            return null;
        }
        try (ZipFile zip = new ZipFile(apk)) {
            ZipEntry entry = zip.getEntry(TEMPLATE_ASSET);
            if (entry == null) {
                return null;
            }
            File temporary = File.createTempFile("qrylz-origin-", ".part", new File(dataDir));
            boolean ok = false;
            try {
                restore(zip, entry, apk, temporary);
                ok = true;
                return temporary;
            } finally {
                if (!ok) {
                    temporary.delete();
                }
            }
        }
    }

    private static void restore(ZipFile zip, ZipEntry entry, File apk, File temporary)
            throws IOException {
        try (DataInputStream in = new DataInputStream(
                new BufferedInputStream(zip.getInputStream(entry)))) {
            if (in.readInt() != TEMPLATE_MAGIC || in.readInt() != TEMPLATE_VERSION) {
                throw new IOException("Bad origin template");
            }
            long originSize = in.readLong();
            if (originSize <= 0 || originSize > Integer.MAX_VALUE) {
                throw new IOException("Bad original size");
            }
            byte[] expected = new byte[32];
            in.readFully(expected);

            MessageDigest digest;
            try {
                digest = MessageDigest.getInstance("SHA-256");
            } catch (NoSuchAlgorithmException e) {
                throw new IOException(e);
            }

            try (RandomAccessFile source = new RandomAccessFile(apk, "r");
                 DigestOutputStream out = new DigestOutputStream(
                         new BufferedOutputStream(new FileOutputStream(temporary)), digest)) {
                Map<String, RawEntry> index = index(source);

                int prefix = in.readInt();
                copy(in, out, prefix, originSize);
                int count = in.readInt();
                if (count <= 0 || count > MAX_ENTRIES) {
                    throw new IOException("Bad template entry count");
                }
                for (int i = 0; i < count; i++) {
                    int nameLength = in.readInt();
                    if (nameLength < 0 || nameLength > 0xFFFF) {
                        throw new IOException("Bad template name");
                    }
                    byte[] nameBytes = new byte[nameLength];
                    in.readFully(nameBytes);
                    String name = new String(nameBytes, StandardCharsets.UTF_8);

                    int headerLength = in.readInt();
                    copy(in, out, headerLength, originSize);

                    int mode = in.readUnsignedByte();
                    int dataLength = in.readInt();
                    if (mode == 1) {
                        copy(in, out, dataLength, originSize);
                    } else if (mode == 0) {
                        RawEntry raw = index.get(name);
                        if (raw == null || raw.size != dataLength) {
                            throw new IOException("The signer changed the data of " + name);
                        }
                        copy(source, out, raw.offset, dataLength);
                    } else {
                        throw new IOException("Bad template mode");
                    }

                    int gapLength = in.readInt();
                    copy(in, out, gapLength, originSize);
                }
                if (in.read() != -1) {
                    throw new IOException("Trailing template data");
                }
            }

            if (temporary.length() != originSize) {
                throw new IOException("The rebuilt apk has the wrong size");
            }
            if (!Arrays.equals(expected, digest.digest())) {
                throw new IOException("The rebuilt apk has the wrong hash");
            }
        }
    }

    private static void copy(InputStream in, OutputStream out, int length, long limit)
            throws IOException {
        if (length < 0 || length > limit) {
            throw new IOException("Bad template length");
        }
        byte[] buffer = new byte[65536];
        int remaining = length;
        while (remaining > 0) {
            int read = in.read(buffer, 0, Math.min(buffer.length, remaining));
            if (read < 0) {
                throw new EOFException();
            }
            out.write(buffer, 0, read);
            remaining -= read;
        }
    }

    private static void copy(RandomAccessFile in, OutputStream out, long offset, int length)
            throws IOException {
        if (offset < 0 || length < 0) {
            throw new IOException("Bad apk offset");
        }
        in.seek(offset);
        byte[] buffer = new byte[65536];
        int remaining = length;
        while (remaining > 0) {
            int read = in.read(buffer, 0, Math.min(buffer.length, remaining));
            if (read < 0) {
                throw new EOFException();
            }
            out.write(buffer, 0, read);
            remaining -= read;
        }
    }

    /**
     * Maps the names in the central directory to the raw compressed data in the apk.
     */
    private static Map<String, RawEntry> index(RandomAccessFile file) throws IOException {
        long length = file.length();
        int tail = (int) Math.min(length, 0xFFFF + 22);
        byte[] buffer = new byte[tail];
        file.seek(length - tail);
        file.readFully(buffer);
        int eocd = -1;
        for (int i = tail - 22; i >= 0; i--) {
            if (u32(buffer, i) == 0x06054b50L) {
                eocd = i;
                break;
            }
        }
        if (eocd < 0) {
            throw new IOException("No end record in the installed apk");
        }
        int count = u16(buffer, eocd + 10);
        long centralSize = u32(buffer, eocd + 12);
        long centralOffset = u32(buffer, eocd + 16);
        if (count == 0xFFFF || centralSize == 0xFFFFFFFFL || centralOffset == 0xFFFFFFFFL) {
            throw new IOException("Zip64 apks are not supported");
        }
        if (centralOffset < 0 || centralOffset + centralSize > length) {
            throw new IOException("Bad central directory");
        }

        Map<String, RawEntry> index = new HashMap<>();
        byte[] header = new byte[46];
        file.seek(centralOffset);
        for (int i = 0; i < count; i++) {
            file.readFully(header);
            if (u32(header, 0) != 0x02014b50L) {
                throw new IOException("Bad central record");
            }
            int nameLength = u16(header, 28);
            int extraLength = u16(header, 30);
            int commentLength = u16(header, 32);
            long compressedSize = u32(header, 20);
            long localOffset = u32(header, 42);
            if (compressedSize == 0xFFFFFFFFL || localOffset == 0xFFFFFFFFL) {
                throw new IOException("Zip64 apks are not supported");
            }
            byte[] name = new byte[nameLength];
            file.readFully(name);
            long next = file.getFilePointer() + extraLength + commentLength;

            file.seek(localOffset);
            file.readFully(header);
            if (u32(header, 0) != 0x04034b50L) {
                throw new IOException("Bad local header");
            }
            int localName = u16(header, 26);
            int localExtra = u16(header, 28);
            long dataOffset = localOffset + 30 + localName + localExtra;
            if (dataOffset < 0 || dataOffset + compressedSize > length) {
                throw new IOException("Bad local data");
            }
            index.put(new String(name, StandardCharsets.UTF_8),
                    new RawEntry(dataOffset, (int) compressedSize));
            file.seek(next);
        }
        return index;
    }

    private static int u16(byte[] data, int offset) {
        return (data[offset] & 0xFF) | ((data[offset + 1] & 0xFF) << 8);
    }

    private static long u32(byte[] data, int offset) {
        return (data[offset] & 0xFFL)
                | ((data[offset + 1] & 0xFFL) << 8)
                | ((data[offset + 2] & 0xFFL) << 16)
                | ((data[offset + 3] & 0xFFL) << 24);
    }

    private static final class RawEntry {
        private final long offset;
        private final int size;

        private RawEntry(long offset, int size) {
            this.offset = offset;
            this.size = size;
        }
    }
}
