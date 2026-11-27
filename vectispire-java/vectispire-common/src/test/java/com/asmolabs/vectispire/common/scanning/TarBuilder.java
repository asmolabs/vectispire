package com.asmolabs.vectispire.common.scanning;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Tar archives of the shapes a Docker daemon writes, for the tests of {@link ImageArchive} — and, through
 * {@code ImagePlatformReferenceSetTest}, the archives the Rust agent's reader is held to.
 */
final class TarBuilder {

    /** How an entry's name reaches the reader. */
    enum Form {
        /** In the header's name field. */
        USTAR,
        /** Split between the POSIX prefix and the name. */
        PREFIX,
        /** In a GNU long-name entry before it, the header's own name cut to 100 bytes. */
        GNU_LONG,
        /** In a PAX header's {@code path}, the header's own name cut to 100 bytes. */
        PAX,
        /** Its size in a PAX header's {@code size}, the header's own size field zero. */
        PAX_SIZE,
        /** A GNU header, whose prefix bytes are not a prefix: garbage there must not reach the name. */
        GNU_MAGIC;

        static Form of(String name) {
            return name == null ? USTAR : valueOf(name.toUpperCase(java.util.Locale.ROOT).replace('-', '_'));
        }
    }

    private final ByteArrayOutputStream out = new ByteArrayOutputStream();

    TarBuilder add(String name, byte[] content) {
        return add(name, content, Form.USTAR, (byte) '0');
    }

    TarBuilder add(String name, byte[] content, Form form, byte type) {
        switch (form) {
            case USTAR -> header(name, "", content.length, type, false);
            case PREFIX -> {
                int slash = name.indexOf('/');
                while (slash >= 0 && name.length() - slash - 1 > 100) {
                    slash = name.indexOf('/', slash + 1);
                }
                if (slash < 0 || slash > 155) {
                    throw new IllegalArgumentException("no prefix split for " + name);
                }
                header(name.substring(slash + 1), name.substring(0, slash), content.length, type, false);
            }
            case GNU_LONG -> {
                byte[] longName = (name + "\0").getBytes(StandardCharsets.UTF_8);
                header("././@LongLink", "", longName.length, (byte) 'L', true);
                data(longName);
                header(cut(name), "", content.length, type, true);
            }
            case PAX -> {
                byte[] records = record("path", name);
                header("PaxHeaders.0/" + cut(name.substring(name.lastIndexOf('/') + 1)), "", records.length, (byte) 'x', false);
                data(records);
                header(cut(name), "", content.length, type, false);
            }
            case PAX_SIZE -> {
                byte[] records = record("size", Integer.toString(content.length));
                header("PaxHeaders.0/size", "", records.length, (byte) 'x', false);
                data(records);
                header(name, "", 0, type, false);
            }
            case GNU_MAGIC -> header(name, "zzz-not-a-prefix", content.length, type, true);
        }
        data(content);
        return this;
    }

    /** The archive, closed by its two zero blocks. */
    byte[] build() {
        byte[] body = withoutEnd();
        return Arrays.copyOf(body, body.length + 1024);
    }

    byte[] withoutEnd() {
        return out.toByteArray();
    }

    private static String cut(String name) {
        byte[] bytes = name.getBytes(StandardCharsets.UTF_8);
        return bytes.length <= 100 ? name : new String(bytes, 0, 100, StandardCharsets.UTF_8);
    }

    /** One PAX record, its length counting its own digits. */
    private static byte[] record(String key, String value) {
        String rest = " " + key + "=" + value + "\n";
        int length = rest.length() + 1;
        while (Integer.toString(length).length() + rest.length() != length) {
            length++;
        }
        return (length + rest).getBytes(StandardCharsets.UTF_8);
    }

    private void header(String name, String prefix, long size, byte type, boolean gnu) {
        byte[] h = new byte[512];
        put(h, 0, name.getBytes(StandardCharsets.UTF_8), 100);
        put(h, 100, "0000644\0".getBytes(StandardCharsets.US_ASCII), 8);
        put(h, 108, "0000000\0".getBytes(StandardCharsets.US_ASCII), 8);
        put(h, 116, "0000000\0".getBytes(StandardCharsets.US_ASCII), 8);
        put(h, 124, String.format("%011o\0", size).getBytes(StandardCharsets.US_ASCII), 12);
        put(h, 136, "00000000000\0".getBytes(StandardCharsets.US_ASCII), 12);
        h[156] = type;
        put(h, 257, (gnu ? "ustar  \0" : "ustar\u000000").getBytes(StandardCharsets.US_ASCII), 8);
        put(h, 345, prefix.getBytes(StandardCharsets.UTF_8), 155);
        Arrays.fill(h, 148, 156, (byte) ' ');
        long sum = 0;
        for (byte b : h) {
            sum += b & 0xff;
        }
        put(h, 148, String.format("%06o\0 ", sum).getBytes(StandardCharsets.US_ASCII), 8);
        out.writeBytes(h);
    }

    private void data(byte[] content) {
        out.writeBytes(content);
        int pad = (512 - content.length % 512) % 512;
        out.writeBytes(new byte[pad]);
    }

    private static void put(byte[] header, int offset, byte[] value, int max) {
        if (value.length > max) {
            throw new IllegalArgumentException("field too long: " + new String(value, StandardCharsets.UTF_8));
        }
        System.arraycopy(value, 0, header, offset, value.length);
    }
}
