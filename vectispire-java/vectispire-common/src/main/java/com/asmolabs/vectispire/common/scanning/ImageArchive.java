package com.asmolabs.vectispire.common.scanning;

import java.io.BufferedInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;

/**
 * One file of the tar archive a Docker daemon writes for a save, read by name — the {@code manifest.json} and the
 * image configurations {@link ImagePlatform#check} compares with the platform asked for.
 *
 * <p><b>Headers only, the layers skipped.</b> An image archive runs to hundreds of megabytes and the two files
 * wanted are a few kilobytes; each lookup walks the headers from the start and reads one entry's bytes, bounded.
 *
 * <p><b>The subset of tar a daemon writes, and nothing more</b>: POSIX ustar names with their prefix, GNU's long
 * name entry, a PAX header's {@code path} and {@code size}, base-256 sizes. Anything else that does not add up —
 * a checksum that does not match, a size that is not a number, an archive cut short — is "not a tar archive",
 * which fails the step: a reader that guessed past it could find a configuration that is not the image's.
 * The Rust agent reads it with the same rules ({@code crates/container/src/image_archive.rs}).
 */
final class ImageArchive {

    private static final int BLOCK = 512;

    /** What a GNU long name or a PAX header may hold; the daemon writes a few hundred bytes at most. */
    private static final int EXTENSION_LIMIT = 64 * 1024;

    static final String NOT_A_TAR_ARCHIVE = "it is not a tar archive";

    /** Why the archive could not be read, in the words {@link ImagePlatform}'s sentence carries. */
    static final class Unreadable extends Exception {
        Unreadable(String why) {
            super(why, null, false, false);
        }
    }

    private ImageArchive() {}

    /**
     * The bytes of the regular file {@code name} (a leading {@code ./} ignored on either side), empty when the
     * archive does not hold it.
     *
     * @throws Unreadable if the archive is not one, or the entry is larger than {@code limit} bytes
     */
    static Optional<byte[]> entry(Path archive, String name, int limit) throws Unreadable {
        try (InputStream in = new BufferedInputStream(Files.newInputStream(archive))) {
            return entry(in, name, limit);
        } catch (IOException unreadable) {
            throw new Unreadable("it could not be read: " + unreadable.getMessage());
        }
    }

    static Optional<byte[]> entry(InputStream in, String name, int limit) throws IOException, Unreadable {
        String wanted = withoutDotSlash(name);
        String pendingName = null;
        long pendingSize = -1;
        byte[] header = new byte[BLOCK];
        while (true) {
            int read = in.readNBytes(header, 0, BLOCK);
            if (read == 0) {
                return Optional.empty();
            }
            if (read < BLOCK) {
                throw new Unreadable(NOT_A_TAR_ARCHIVE);
            }
            if (allZero(header)) {
                return Optional.empty();
            }
            if (checksum(header) != storedChecksum(header)) {
                throw new Unreadable(NOT_A_TAR_ARCHIVE);
            }
            long size = number(header, 124, 12);
            byte type = header[156];
            switch (type) {
                case 'L' -> {
                    pendingName = cString(extension(in, size), 0, (int) size);
                    continue;
                }
                case 'x' -> {
                    byte[] records = extension(in, size);
                    Pax pax = pax(records);
                    if (pax.path != null) {
                        pendingName = pax.path;
                    }
                    if (pax.size >= 0) {
                        pendingSize = pax.size;
                    }
                    continue;
                }
                default -> {}
            }
            String entryName = pendingName != null ? pendingName : headerName(header);
            long entrySize = pendingSize >= 0 ? pendingSize : size;
            pendingName = null;
            pendingSize = -1;
            boolean regular = type == '0' || type == 0;
            if (regular && withoutDotSlash(entryName).equals(wanted)) {
                if (entrySize > limit) {
                    throw new Unreadable(wanted + " is larger than " + limit + " bytes");
                }
                byte[] content = in.readNBytes((int) entrySize);
                if (content.length < entrySize) {
                    throw new Unreadable(NOT_A_TAR_ARCHIVE);
                }
                return Optional.of(content);
            }
            skip(in, padded(entrySize));
        }
    }

    /** A GNU long name's or a PAX header's data, padding consumed. */
    private static byte[] extension(InputStream in, long size) throws IOException, Unreadable {
        if (size > EXTENSION_LIMIT) {
            throw new Unreadable(NOT_A_TAR_ARCHIVE);
        }
        byte[] data = in.readNBytes((int) size);
        if (data.length < size) {
            throw new Unreadable(NOT_A_TAR_ARCHIVE);
        }
        skip(in, padded(size) - size);
        return data;
    }

    private record Pax(String path, long size) {}

    /** {@code "<length> <key>=<value>\n"} records, the length counting the whole record. */
    private static Pax pax(byte[] records) throws Unreadable {
        String path = null;
        long size = -1;
        int at = 0;
        while (at < records.length) {
            int space = at;
            while (space < records.length && records[space] != ' ') {
                space++;
            }
            long length = decimal(records, at, space);
            if (length <= space - at || at + length > records.length || records[(int) (at + length - 1)] != '\n') {
                throw new Unreadable(NOT_A_TAR_ARCHIVE);
            }
            String record = new String(records, space + 1, (int) (at + length - 1 - (space + 1)), StandardCharsets.UTF_8);
            int equals = record.indexOf('=');
            if (equals < 0) {
                throw new Unreadable(NOT_A_TAR_ARCHIVE);
            }
            String key = record.substring(0, equals);
            String value = record.substring(equals + 1);
            if (key.equals("path")) {
                path = value;
            } else if (key.equals("size")) {
                byte[] digits = value.getBytes(StandardCharsets.UTF_8);
                size = decimal(digits, 0, digits.length);
            }
            at += (int) length;
        }
        return new Pax(path, size);
    }

    /** A non-empty run of ASCII digits, below 2^62. */
    private static long decimal(byte[] bytes, int from, int to) throws Unreadable {
        if (from >= to || to - from > 18) {
            throw new Unreadable(NOT_A_TAR_ARCHIVE);
        }
        long value = 0;
        for (int i = from; i < to; i++) {
            if (bytes[i] < '0' || bytes[i] > '9') {
                throw new Unreadable(NOT_A_TAR_ARCHIVE);
            }
            value = value * 10 + (bytes[i] - '0');
        }
        return value;
    }

    /**
     * A numeric field: octal digits between optional spaces and NULs, or base-256 when its first byte has the high
     * bit — a size of 8 GiB or more. A negative or overflowing number is not a size.
     */
    static long number(byte[] header, int offset, int length) throws Unreadable {
        if ((header[offset] & 0x80) != 0) {
            if ((header[offset] & 0x40) != 0) {
                throw new Unreadable(NOT_A_TAR_ARCHIVE);
            }
            long value = header[offset] & 0x3f;
            for (int i = offset + 1; i < offset + length; i++) {
                if (value > (Long.MAX_VALUE >> 8)) {
                    throw new Unreadable(NOT_A_TAR_ARCHIVE);
                }
                value = (value << 8) | (header[i] & 0xff);
            }
            return value;
        }
        int from = offset;
        int to = offset + length;
        while (from < to && (header[from] == ' ' || header[from] == 0)) {
            from++;
        }
        while (to > from && (header[to - 1] == ' ' || header[to - 1] == 0)) {
            to--;
        }
        long value = 0;
        for (int i = from; i < to; i++) {
            if (header[i] < '0' || header[i] > '7') {
                throw new Unreadable(NOT_A_TAR_ARCHIVE);
            }
            value = value * 8 + (header[i] - '0');
        }
        return value;
    }

    private static long storedChecksum(byte[] header) throws Unreadable {
        return number(header, 148, 8);
    }

    /** The sum of the header's unsigned bytes, its own checksum field counted as spaces. */
    private static long checksum(byte[] header) {
        long sum = 0;
        for (int i = 0; i < BLOCK; i++) {
            sum += (i >= 148 && i < 156) ? ' ' : (header[i] & 0xff);
        }
        return sum;
    }

    /** The name, behind its ustar prefix when the header is POSIX's (GNU's uses those bytes otherwise). */
    private static String headerName(byte[] header) {
        String name = cString(header, 0, 100);
        boolean posix = header[257] == 'u' && header[258] == 's' && header[259] == 't' && header[260] == 'a'
                && header[261] == 'r' && header[262] == 0;
        if (posix) {
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

    private static String withoutDotSlash(String name) {
        return name.startsWith("./") ? name.substring(2) : name;
    }

    private static boolean allZero(byte[] block) {
        for (byte b : block) {
            if (b != 0) {
                return false;
            }
        }
        return true;
    }

    private static long padded(long size) {
        return (size + BLOCK - 1) / BLOCK * BLOCK;
    }

    private static void skip(InputStream in, long count) throws IOException, Unreadable {
        try {
            in.skipNBytes(count);
        } catch (EOFException cut) {
            throw new Unreadable(NOT_A_TAR_ARCHIVE);
        }
    }
}
