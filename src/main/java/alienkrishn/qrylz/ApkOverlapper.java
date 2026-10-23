package alienkrishn.qrylz;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.zip.CRC32;

/**
 * Builds an APK that keeps the original apk as a prefix.
 * <p>
 * The output is laid out like this:
 * <pre>
 *   [ the original apk, byte for byte ][ the new entries ][ central directory ][ end record ]
 * </pre>
 * The first part is a complete, validly signed apk - the original one. It costs nothing
 * extra, because it is the same bytes the apk would have anyway, and the new entries are
 * appended after it. A hook that serves the first {@code originSize} bytes of the file
 * therefore serves the untouched original apk, which is what a check that reads the
 * certificate out of the apk file needs.
 * <p>
 * The central directory is written again, with the entry that was replaced pointing at the
 * new one. The size of the result is the size of the original plus the new entries plus
 * one more central directory.
 */
public final class ApkOverlapper {

    private static final int EOCD_SIZE = 22;
    private static final int CENTRAL_HEADER_SIZE = 46;
    private static final int LOCAL_HEADER_SIZE = 30;
    private static final int ZIP64_EOCD_LOCATOR_SIZE = 20;
    private static final String ORIGIN_TEMPLATE = "assets/qrylz_origin.bin";
    private static final int TEMPLATE_MAGIC = 0x51524F54;
    private static final int TEMPLATE_VERSION = 1;

    private ApkOverlapper() {
    }

    /**
     * One entry of the new apk.
     */
    public static final class NewEntry {
        private final String name;
        private final byte[] data;

        public NewEntry(String name, byte[] data) {
            this.name = name;
            this.data = data;
        }
    }

    /**
     * Writes the new apk.
     *
     * @param original   the original apk
     * @param output     the file to write
     * @param newEntries the entries to add or replace
     * @return the size of the original apk inside the new file
     * @throws IOException when the files cannot be read or written
     */
    public static long write(File original, File output, List<NewEntry> newEntries)
            throws IOException {
        byte[] source = Files.readAllBytes(original.toPath());

        // The end of central directory record is at the end of the file.
        int eocd = findEndOfCentralDirectory(source);
        if (eocd < 0) {
            throw new IOException("Not a zip file: " + original);
        }
        int entryCount = readShort(source, eocd + 10);
        int centralSize = readInt(source, eocd + 12);
        int centralOffset = readInt(source, eocd + 16);

        // Zip64 files store the real values in a separate record.
        if (centralOffset == 0xFFFFFFFF || centralSize == 0xFFFFFFFF || entryCount == 0xFFFF) {
            int locator = eocd - ZIP64_EOCD_LOCATOR_SIZE;
            if (locator >= 0 && readInt(source, locator) == 0x07064b50) {
                long zip64 = readLong(source, locator + 8);
                entryCount = (int) readLong(source, (int) zip64 + 32);
                centralSize = (int) readLong(source, (int) zip64 + 40);
                centralOffset = (int) readLong(source, (int) zip64 + 48);
            }
        }

        // The output starts with the whole input file, including a zip comment or any
        // trailing bytes, so the template has to cover those bytes too.
        long originSize = source.length;

        // The template lets the payload rebuild the original apk even after a signer
        // repacked the zip and moved every entry: the signer keeps the compressed
        // bytes, so they are copied from the installed apk, and the few entries the
        // signer replaces or strips are stored in the template.
        List<NewEntry> entries = new ArrayList<>(newEntries.size() + 1);
        entries.addAll(newEntries);
        if (!contains(entries, ORIGIN_TEMPLATE)) {
            entries.add(new NewEntry(ORIGIN_TEMPLATE,
                    originTemplate(source, centralOffset, centralSize, (int) originSize)));
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream(source.length + 1024);
        out.write(source);

        // The new entries, written as local file headers with their data.
        List<Object[]> written = new ArrayList<>();
        for (NewEntry entry : entries) {
            long offset = out.size();
            CRC32 crc = new CRC32();
            crc.update(entry.data);
            writeLocalHeader(out, entry, crc);
            written.add(new Object[]{entry.name, offset, entry.data.length, (int) crc.getValue()});
        }

        // The central directory of the original is rebuilt without the entries that
        // were replaced, they are added again with the new data. The old v1 signature
        // entries are left out of it too: a signer removes them from the zip, which
        // would shift the prefix and make it stop being the original apk. Their local
        // bytes stay in the prefix, so the prefix is still a complete signed apk.
        long centralStart = out.size();
        byte[] central = buildCentralDirectory(source, centralOffset, centralSize, written);
        int replaced = countReplaced(source, centralOffset, centralSize, written);
        int signatures = countSignatures(source, centralOffset, centralSize, written);

        // The central directory of the original, without the entries that were
        // replaced, followed by the records of the new entries.
        out.write(central, 0, central.length);

        for (Object[] item : written) {
            String name = (String) item[0];
            long offset = (Long) item[1];
            int size = (Integer) item[2];
            int crc = (Integer) item[3];
            writeCentralHeader(out, name, size, offset, crc);
        }
        long centralEnd = out.size();

        // The end record.
        int count = entryCount - replaced - signatures + written.size();
        ByteArrayOutputStream end = new ByteArrayOutputStream(EOCD_SIZE);
        writeInt(end, 0x06054b50);
        writeShort(end, 0);
        writeShort(end, 0);
        writeShort(end, count);
        writeShort(end, count);
        writeInt(end, (int) (centralEnd - centralStart));
        writeInt(end, (int) centralStart);
        writeShort(end, 0);
        out.write(end.toByteArray());

        Files.write(output.toPath(), out.toByteArray());
        return originSize;
    }

    private static boolean contains(List<NewEntry> entries, String name) {
        for (NewEntry entry : entries) {
            if (entry.name.equals(name)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Builds the data that lets the payload rebuild the original apk from the installed
     * one.
     * <p>
     * Every original local header is stored with the gap that follows its data, and the
     * last gap holds the signing block, the central directory and the end record. Data
     * is copied from the installed apk by name, except for the entries that a signer
     * changes - the manifest and the v1 signatures - which are stored here.
     */
    private static byte[] originTemplate(byte[] source, int centralOffset, int centralSize,
                                         int originSize) throws IOException {
        List<Object[]> items = new ArrayList<>();
        int position = centralOffset;
        int end = centralOffset + centralSize;
        while (position + CENTRAL_HEADER_SIZE <= end) {
            if (readInt(source, position) != 0x02014b50) {
                break;
            }
            int nameLength = readShort(source, position + 28);
            int extraLength = readShort(source, position + 30);
            int commentLength = readShort(source, position + 32);
            int compressedSize = readInt(source, position + 20);
            int localOffset = readInt(source, position + 42);
            String name = new String(source, position + CENTRAL_HEADER_SIZE, nameLength,
                    StandardCharsets.UTF_8);
            if (localOffset < 0 || localOffset + LOCAL_HEADER_SIZE > originSize
                    || readInt(source, localOffset) != 0x04034b50) {
                throw new IOException("Bad local header for " + name);
            }
            int localName = readShort(source, localOffset + 26);
            int localExtra = readShort(source, localOffset + 28);
            int dataOffset = localOffset + LOCAL_HEADER_SIZE + localName + localExtra;
            int dataEnd = dataOffset + compressedSize;
            if (dataEnd < dataOffset || dataEnd > originSize) {
                throw new IOException("Bad compressed size for " + name);
            }
            items.add(new Object[]{localOffset, name, dataOffset, dataEnd});
            position += CENTRAL_HEADER_SIZE + nameLength + extraLength + commentLength;
        }
        if (items.isEmpty()) {
            throw new IOException("No entries in the original apk");
        }
        items.sort(Comparator.comparingInt(item -> (Integer) item[0]));

        ByteArrayOutputStream buffer = new ByteArrayOutputStream(originSize / 16);
        try (DataOutputStream out = new DataOutputStream(buffer)) {
            out.writeInt(TEMPLATE_MAGIC);
            out.writeInt(TEMPLATE_VERSION);
            out.writeLong(originSize);
            MessageDigest digest;
            try {
                digest = MessageDigest.getInstance("SHA-256");
            } catch (NoSuchAlgorithmException e) {
                throw new IOException(e);
            }
            digest.update(source, 0, originSize);
            out.write(digest.digest());

            int cursor = 0;
            int first = (Integer) items.get(0)[0];
            out.writeInt(first);
            out.write(source, 0, first);
            out.writeInt(items.size());
            for (int i = 0; i < items.size(); i++) {
                Object[] item = items.get(i);
                int localOffset = (Integer) item[0];
                String name = (String) item[1];
                int dataOffset = (Integer) item[2];
                int dataEnd = (Integer) item[3];
                if (localOffset < cursor) {
                    throw new IOException("Overlapping entries in the original apk");
                }
                int next = i + 1 < items.size() ? (Integer) items.get(i + 1)[0] : originSize;
                if (next < dataEnd) {
                    throw new IOException("Overlapping entries in the original apk");
                }
                byte[] nameBytes = name.getBytes(StandardCharsets.UTF_8);
                out.writeInt(nameBytes.length);
                out.write(nameBytes, 0, nameBytes.length);
                out.writeInt(dataOffset - localOffset);
                out.write(source, localOffset, dataOffset - localOffset);
                boolean embedded = isOriginEmbedded(name);
                out.writeByte(embedded ? 1 : 0);
                out.writeInt(dataEnd - dataOffset);
                if (embedded) {
                    out.write(source, dataOffset, dataEnd - dataOffset);
                }
                out.writeInt(next - dataEnd);
                out.write(source, dataEnd, next - dataEnd);
                cursor = next;
            }
        }
        return buffer.toByteArray();
    }

    private static boolean isOriginEmbedded(String name) {
        return name.equals("AndroidManifest.xml") || name.equals(ORIGIN_TEMPLATE)
                || name.equals("stamp-cert-sha256") || isSignature(name);
    }

    /**
     * Rebuilds the central directory of the original without the entries that are
     * replaced.
     */
    private static byte[] buildCentralDirectory(byte[] source, int centralOffset, int centralSize,
                                                List<Object[]> written) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(centralSize);
        int position = centralOffset;
        int end = centralOffset + centralSize;
        while (position + CENTRAL_HEADER_SIZE <= end) {
            if (readInt(source, position) != 0x02014b50) {
                break;
            }
            int nameLength = readShort(source, position + 28);
            int extraLength = readShort(source, position + 30);
            int commentLength = readShort(source, position + 32);
            int recordLength = CENTRAL_HEADER_SIZE + nameLength + extraLength + commentLength;
            String name = new String(source, position + CENTRAL_HEADER_SIZE, nameLength,
                    StandardCharsets.UTF_8);

            boolean replaced = false;
            for (Object[] item : written) {
                if (name.equals(item[0])) {
                    replaced = true;
                    break;
                }
            }
            if (!replaced && !isSignature(name)) {
                out.write(source, position, recordLength);
            }
            position += recordLength;
        }
        return out.toByteArray();
    }

    /**
     * @return how many old v1 signature entries are hidden from the new central directory
     */
    private static int countSignatures(byte[] source, int centralOffset, int centralSize,
                                       List<Object[]> written) {
        int position = centralOffset;
        int end = centralOffset + centralSize;
        int count = 0;
        while (position + CENTRAL_HEADER_SIZE <= end) {
            if (readInt(source, position) != 0x02014b50) {
                break;
            }
            int nameLength = readShort(source, position + 28);
            int extraLength = readShort(source, position + 30);
            int commentLength = readShort(source, position + 32);
            String name = new String(source, position + CENTRAL_HEADER_SIZE, nameLength,
                    StandardCharsets.UTF_8);
            if (isSignature(name) && !isWritten(name, written)) {
                count++;
            }
            position += CENTRAL_HEADER_SIZE + nameLength + extraLength + commentLength;
        }
        return count;
    }

    private static boolean isWritten(String name, List<Object[]> written) {
        for (Object[] item : written) {
            if (name.equals(item[0])) {
                return true;
            }
        }
        return false;
    }

    /**
     * @return true for a v1 signature file of the original apk
     */
    private static boolean isSignature(String name) {
        String upper = name.toUpperCase(java.util.Locale.US);
        if (upper.equals("META-INF/MANIFEST.MF")) {
            return true;
        }
        if (!upper.startsWith("META-INF/")) {
            return false;
        }
        return upper.endsWith(".SF") || upper.endsWith(".RSA")
                || upper.endsWith(".DSA") || upper.endsWith(".EC");
    }

    /**
     * @return how many entries of the original are replaced
     */
    private static int countReplaced(byte[] source, int centralOffset, int centralSize,
                                     List<Object[]> written) {
        int position = centralOffset;
        int end = centralOffset + centralSize;
        int count = 0;
        while (position + CENTRAL_HEADER_SIZE <= end) {
            if (readInt(source, position) != 0x02014b50) {
                break;
            }
            int nameLength = readShort(source, position + 28);
            int extraLength = readShort(source, position + 30);
            int commentLength = readShort(source, position + 32);
            String name = new String(source, position + CENTRAL_HEADER_SIZE, nameLength,
                    StandardCharsets.UTF_8);
            for (Object[] item : written) {
                if (name.equals(item[0])) {
                    count++;
                    break;
                }
            }
            position += CENTRAL_HEADER_SIZE + nameLength + extraLength + commentLength;
        }
        return count;
    }

    private static void writeLocalHeader(ByteArrayOutputStream out, NewEntry entry, CRC32 crc) {
        byte[] name = entry.name.getBytes(StandardCharsets.UTF_8);
        // The data of the entry has to start on the alignment the platform wants:
        // a native library is mapped straight out of the apk, so it needs a page.
        // 16 KB is a multiple of the 4 KB page size, so it works on both.
        int alignment = entry.name.endsWith(".so") ? 16384 : 4;
        int headerSize = LOCAL_HEADER_SIZE + name.length;
        int padding = (alignment - ((int) (out.size() + headerSize) % alignment)) % alignment;
        // A zip extra field needs at least its four byte header. Adding one alignment
        // keeps the data aligned.
        if (padding > 0 && padding < 4) {
            padding += alignment;
        }
        byte[] extra = padding > 0 ? padding(padding) : new byte[0];

        writeInt(out, 0x04034b50);
        writeShort(out, 20);
        writeShort(out, 0);
        writeShort(out, 0);              // stored
        writeShort(out, 0);
        writeShort(out, 0);
        writeInt(out, (int) crc.getValue());
        writeInt(out, entry.data.length);
        writeInt(out, entry.data.length);
        writeShort(out, name.length);
        writeShort(out, extra.length);
        out.write(name, 0, name.length);
        out.write(extra, 0, extra.length);
        out.write(entry.data, 0, entry.data.length);
    }

    /**
     * Builds the extra field that pads the entry to its alignment.
     * <p>
     * The header id is the one the platform tools use for the alignment padding.
     */
    private static byte[] padding(int size) {
        byte[] extra = new byte[size];
        if (size >= 4) {
            extra[0] = (byte) 0x35;
            extra[1] = (byte) 0xd9;
            extra[2] = (byte) ((size - 4) & 0xFF);
            extra[3] = (byte) (((size - 4) >> 8) & 0xFF);
        }
        return extra;
    }

    private static void writeCentralHeader(ByteArrayOutputStream out, String name, int size,
                                           long offset, int crc) {
        byte[] nameBytes = name.getBytes(StandardCharsets.UTF_8);
        writeInt(out, 0x02014b50);
        writeShort(out, 20);
        writeShort(out, 20);
        writeShort(out, 0);
        writeShort(out, 0);
        writeShort(out, 0);
        writeShort(out, 0);
        writeInt(out, crc);
        writeInt(out, size);
        writeInt(out, size);
        writeShort(out, nameBytes.length);
        writeShort(out, 0);
        writeShort(out, 0);
        writeShort(out, 0);
        writeShort(out, 0);
        writeInt(out, 0);
        writeInt(out, (int) offset);
        out.write(nameBytes, 0, nameBytes.length);
    }

    private static int findEndOfCentralDirectory(byte[] data) {
        int limit = Math.max(0, data.length - 0xFFFF - EOCD_SIZE - 1);
        for (int i = data.length - EOCD_SIZE; i >= limit; i--) {
            if (readInt(data, i) == 0x06054b50) {
                return i;
            }
        }
        return -1;
    }

    private static int readShort(byte[] data, int offset) {
        return (data[offset] & 0xFF) | ((data[offset + 1] & 0xFF) << 8);
    }

    private static int readInt(byte[] data, int offset) {
        return (data[offset] & 0xFF)
                | ((data[offset + 1] & 0xFF) << 8)
                | ((data[offset + 2] & 0xFF) << 16)
                | ((data[offset + 3] & 0xFF) << 24);
    }

    private static long readLong(byte[] data, int offset) {
        return (readInt(data, offset) & 0xFFFFFFFFL) | ((long) readInt(data, offset + 4) << 32);
    }

    private static void setInt(byte[] data, int offset, int value) {
        data[offset] = (byte) (value & 0xFF);
        data[offset + 1] = (byte) ((value >> 8) & 0xFF);
        data[offset + 2] = (byte) ((value >> 16) & 0xFF);
        data[offset + 3] = (byte) ((value >> 24) & 0xFF);
    }

    private static void writeShort(ByteArrayOutputStream out, int value) {
        out.write(value & 0xFF);
        out.write((value >> 8) & 0xFF);
    }

    private static void writeInt(ByteArrayOutputStream out, int value) {
        out.write(value & 0xFF);
        out.write((value >> 8) & 0xFF);
        out.write((value >> 16) & 0xFF);
        out.write((value >> 24) & 0xFF);
    }
}
