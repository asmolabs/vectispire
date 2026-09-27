package com.asmolabs.vectispire.common.scanning;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/**
 * Reads the one file the archive API answers for a path of a bounded output directory.
 *
 * <p><b>Written here rather than taken from a library</b>: the stream is what one daemon writes for
 * one path, what is needed is the first entry's header and its bytes, and this module's dependency
 * list is the one its build script calls the hardest review. What it understands is what Go's
 * {@code archive/tar} writes: ustar headers, a PAX extended header overriding the entry's path or
 * size, a GNU long name, base-256 sizes.
 *
 * <p><b>The daemon does not follow a link</b> when it archives a path (measured: a link named like
 * the report comes back as a link entry), so a plugin cannot make this read anything but what it
 * wrote. The entry must be a regular file of that name; a link, a directory, a FIFO are refused.
 *
 * <p><b>The size is checked on the header, before a byte of content is read.</b> The file's
 * apparent size is bounded by the tool's {@code fsize} limit — the directory's capacity — so what
 * the transport drains when the stream is closed early is bounded too: a tmpfs keeps a sparse file
 * far larger than its size, and without that limit a {@code truncate -s 1T} would have been a
 * terabyte of zeros read back.
 */
final class OutputArchive {

    private static final int BLOCK = 512;

    /** A PAX header or a long name is a few hundred bytes; more is not a header. */
    private static final int MAX_META = 64 * 1024;

    private OutputArchive() {}

    /**
     * @param file the name the entry must carry — the archived path's last segment
     * @param ceiling what the file may weigh
     */
    static ContainerRunner.OutputFile read(InputStream tar, String file, long ceiling) throws IOException {
        String pendingName = null;
        Long pendingSize = null;
        byte[] header = new byte[BLOCK];
        while (readBlock(tar, header) && !isZero(header)) {
            char type = (char) header[156];
            long size = size(header);
            if (type == 'x' || type == 'L') {
                byte[] meta = content(tar, size, MAX_META);
                if (type == 'L') {
                    pendingName = cString(meta, 0, meta.length);
                } else {
                    String path = paxValue(meta, "path");
                    String paxSize = paxValue(meta, "size");
                    pendingName = path != null ? path : pendingName;
                    pendingSize = paxSize != null ? parseLong(paxSize) : pendingSize;
                }
                continue;
            }
            if (type == 'g') {
                content(tar, size, MAX_META);
                continue;
            }
            String name = pendingName != null ? pendingName : name(header);
            if (pendingSize != null) {
                size = pendingSize;
            }
            boolean regular = type == '0' || type == '\0';
            if (!regular || !name.equals(file)) {
                return new ContainerRunner.OutputFile.NotRegular();
            }
            if (size > ceiling) {
                return new ContainerRunner.OutputFile.TooLarge(size);
            }
            return new ContainerRunner.OutputFile.Read(content(tar, size, ceiling));
        }
        return new ContainerRunner.OutputFile.Missing();
    }


    private static boolean readBlock(InputStream in, byte[] block) throws IOException {
        int read = in.readNBytes(block, 0, BLOCK);
        if (read == 0) {
            return false;
        }
        if (read < BLOCK) {
            throw new EOFException("The output archive ends inside a header.");
        }
        return true;
    }

    private static boolean isZero(byte[] block) {
        for (byte b : block) {
            if (b != 0) {
                return false;
            }
        }
        return true;
    }

    private static byte[] content(InputStream in, long size, long ceiling) throws IOException {
        if (size < 0 || size > ceiling) {
            throw new IOException("An entry of the output archive is larger than it may be.");
        }
        byte[] bytes = in.readNBytes((int) size);
        if (bytes.length < size) {
            throw new EOFException("The output archive ends inside an entry.");
        }
        skipPadding(in, size);
        return bytes;
    }

    private static void skipPadding(InputStream in, long size) throws IOException {
        long remainder = size % BLOCK;
        if (remainder != 0) {
            in.skipNBytes(BLOCK - remainder);
        }
    }

    /** Octal, or base-256 when the high bit of the first byte is set — GNU's form for large files. */
    private static long size(byte[] header) throws IOException {
        if ((header[124] & 0x80) != 0) {
            long value = header[124] & 0x7f;
            for (int i = 125; i < 136; i++) {
                if (value > (Long.MAX_VALUE >> 8)) {
                    throw new IOException("An entry of the output archive declares an impossible size.");
                }
                value = (value << 8) | (header[i] & 0xff);
            }
            return value;
        }
        String octal = cString(header, 124, 12).strip();
        if (octal.isEmpty()) {
            return 0;
        }
        try {
            return Long.parseLong(octal, 8);
        } catch (NumberFormatException malformed) {
            throw new IOException("An entry of the output archive declares no readable size.");
        }
    }

    private static String name(byte[] header) {
        String name = cString(header, 0, 100);
        String magic = cString(header, 257, 6);
        if (magic.startsWith("ustar")) {
            String prefix = cString(header, 345, 155);
            if (!prefix.isEmpty()) {
                return prefix + "/" + name;
            }
        }
        return name;
    }

    private static String cString(byte[] bytes, int offset, int length) {
        int end = offset;
        while (end < offset + length && bytes[end] != 0) {
            end++;
        }
        return new String(bytes, offset, end - offset, StandardCharsets.UTF_8);
    }

    /**
     * A PAX record is {@code "<length> <key>=<value>\n"}, the length counting the record's bytes —
     * bytes, not characters, so the records are walked as bytes.
     */
    private static String paxValue(byte[] meta, String key) throws IOException {
        int at = 0;
        while (at < meta.length) {
            int space = at;
            while (space < meta.length && meta[space] != ' ') {
                space++;
            }
            if (space == meta.length) {
                break;
            }
            int length;
            try {
                length = Integer.parseInt(new String(meta, at, space - at, StandardCharsets.US_ASCII));
            } catch (NumberFormatException malformed) {
                throw new IOException("The output archive carries a malformed extended header.");
            }
            if (length <= space - at + 1 || at + length > meta.length) {
                throw new IOException("The output archive carries a malformed extended header.");
            }
            String record = new String(meta, space + 1, at + length - space - 2, StandardCharsets.UTF_8);
            int equals = record.indexOf('=');
            if (equals > 0 && record.substring(0, equals).equals(key)) {
                return record.substring(equals + 1);
            }
            at += length;
        }
        return null;
    }

    private static long parseLong(String value) throws IOException {
        try {
            return Long.parseLong(value.strip());
        } catch (NumberFormatException malformed) {
            throw new IOException("The output archive carries a malformed extended header.");
        }
    }
}
