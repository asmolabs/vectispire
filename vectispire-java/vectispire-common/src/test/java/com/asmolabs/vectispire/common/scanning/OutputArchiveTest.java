package com.asmolabs.vectispire.common.scanning;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * Reading a bounded output back: the archive's one entry, and the holder's {@code df}.
 *
 * <p>The archives here are built by hand, header by header, because each case is a header a daemon
 * could send and a plugin could provoke; the real daemon's archive is read by the container suite.
 */
@DisplayName("a bounded output, read back")
class OutputArchiveTest {

    private static final String REPORT = "{\"version\":\"2.1.0\",\"runs\":[]}";

    /** A ustar header: name, size in octal, type — the fields the reader reads. */
    private static byte[] header(String name, long size, char type) {
        byte[] header = new byte[512];
        byte[] bytes = name.getBytes(StandardCharsets.UTF_8);
        System.arraycopy(bytes, 0, header, 0, bytes.length);
        byte[] octal = String.format("%011o", size).getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(octal, 0, header, 124, octal.length);
        header[156] = (byte) type;
        System.arraycopy("ustar".getBytes(StandardCharsets.US_ASCII), 0, header, 257, 5);
        return header;
    }

    private static byte[] tar(Object... parts) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (Object part : parts) {
            byte[] bytes = part instanceof String text ? text.getBytes(StandardCharsets.UTF_8) : (byte[]) part;
            out.write(bytes);
            if (part instanceof String) {
                out.write(new byte[(512 - bytes.length % 512) % 512]);
            }
        }
        out.write(new byte[1024]);
        return out.toByteArray();
    }

    private static ContainerRunner.OutputFile read(byte[] tar, long ceiling) throws IOException {
        return OutputArchive.read(new ByteArrayInputStream(tar), "results.sarif", ceiling);
    }

    @Test
    @DisplayName("the report as the daemon archives it: one regular entry of its name")
    void regular() throws IOException {
        ContainerRunner.OutputFile file = read(tar(header("results.sarif", REPORT.length(), '0'), REPORT), 1024);

        assertThat(file).isInstanceOfSatisfying(ContainerRunner.OutputFile.Read.class,
                read -> assertThat(new String(read.bytes(), StandardCharsets.UTF_8)).isEqualTo(REPORT));
    }

    @Test
    @DisplayName("a link named like the report is not read — the daemon archives a link as a link")
    void link() throws IOException {
        assertThat(read(tar(header("results.sarif", 0, '2')), 1024)).isInstanceOf(ContainerRunner.OutputFile.NotRegular.class);
    }

    @Test
    @DisplayName("a directory, a FIFO, or an entry of another name is not the report")
    void notTheReport() throws IOException {
        assertThat(read(tar(header("results.sarif/", 0, '5')), 1024)).isInstanceOf(ContainerRunner.OutputFile.NotRegular.class);
        assertThat(read(tar(header("results.sarif", 0, '6')), 1024)).isInstanceOf(ContainerRunner.OutputFile.NotRegular.class);
        assertThat(read(tar(header("other.sarif", REPORT.length(), '0'), REPORT), 1024))
                .isInstanceOf(ContainerRunner.OutputFile.NotRegular.class);
    }

    @Test
    @DisplayName("an oversized report is refused on its header: not a byte of its content is read")
    void oversized() throws IOException {
        // Eight gigabytes declared — the most an octal size spells — and no content behind it: reading
        // any of it would hit the end of the stream.
        byte[] archive = header("results.sarif", (1L << 33) - 1, '0');

        assertThat(read(archive, 1024)).isInstanceOfSatisfying(ContainerRunner.OutputFile.TooLarge.class,
                tooLarge -> assertThat(tooLarge.size()).isEqualTo((1L << 33) - 1));
    }

    @Test
    @DisplayName("a base-256 size, GNU's form for large files, is read as a size and not as zero")
    void base256() throws IOException {
        byte[] archive = header("results.sarif", 0, '0');
        java.util.Arrays.fill(archive, 124, 136, (byte) 0);
        archive[124] = (byte) 0x80;
        archive[131] = 0x01; // 1 << 32

        assertThat(read(archive, 1024)).isInstanceOfSatisfying(ContainerRunner.OutputFile.TooLarge.class,
                tooLarge -> assertThat(tooLarge.size()).isEqualTo(1L << 32));
    }

    @Test
    @DisplayName("a PAX header's path and size override the entry's own — the size bound included")
    void pax() throws IOException {
        String records = pax("path", "results.sarif") + pax("size", String.valueOf(1L << 40));
        byte[] archive = tar(header("PaxHeaders/x", records.getBytes(StandardCharsets.UTF_8).length, 'x'), records,
                header("results.sar", 0, '0'));

        assertThat(read(archive, 1024)).isInstanceOf(ContainerRunner.OutputFile.TooLarge.class);
    }

    @Test
    @DisplayName("an empty archive is no report")
    void missing() throws IOException {
        assertThat(read(new byte[0], 1024)).isInstanceOf(ContainerRunner.OutputFile.Missing.class);
        assertThat(read(new byte[1024], 1024)).isInstanceOf(ContainerRunner.OutputFile.Missing.class);
    }

    @Test
    @DisplayName("an archive cut inside the report is an error, never a shorter report")
    void truncated() {
        byte[] archive = new byte[512 + 10];
        System.arraycopy(header("results.sarif", REPORT.length(), '0'), 0, archive, 0, 512);

        assertThatThrownBy(() -> read(archive, 1024)).isInstanceOf(EOFException.class);
    }

    /** One PAX record: the length counts itself. */
    private static String pax(String key, String value) {
        String body = " " + key + "=" + value + "\n";
        int length = body.length() + 1;
        while (String.valueOf(length).length() + body.length() != length) {
            length++;
        }
        return length + body;
    }

    @Nested
    @DisplayName("the holder's measure")
    class Measure {

        private final ContainerRun.BoundedOutput bounded =
                new ContainerRun.BoundedOutput("/repo/output", 1 << 20, "busybox@sha256:" + "0".repeat(64), "results.sarif");

        private static final String DF = """
                Filesystem           1024-blocks    Used Available Capacity Mounted on
                tmpfs                     1024      %d      %d  %d%% /repo/output
                Filesystem              Inodes      Used Available Capacity Mounted on
                tmpfs                     4096      %d      %d   1%% /repo/output
                """;

        @Test
        @DisplayName("space left and inodes left, in the kernel's words")
        void room() {
            ContainerRunner.CollectedOutput output = ContainerRunner.CollectedOutput
                    .measured(bounded, DF.formatted(24, 1000, 3, 3, 4093), new ContainerRunner.OutputFile.Missing())
                    .orElseThrow();

            assertThat(output.availableBytes()).isEqualTo(1000 * 1024);
            assertThat(output.availableInodes()).isEqualTo(4093);
            assertThat(output.full()).isFalse();
        }

        @Test
        @DisplayName("no page left, or no inode left, is full")
        void full() {
            assertThat(ContainerRunner.CollectedOutput.measured(bounded, DF.formatted(1021, 3, 100, 3, 4093),
                    new ContainerRunner.OutputFile.Missing()).orElseThrow().full()).isTrue();
            assertThat(ContainerRunner.CollectedOutput.measured(bounded, DF.formatted(24, 1000, 3, 4096, 0),
                    new ContainerRunner.OutputFile.Missing()).orElseThrow().full()).isTrue();
        }

        @Test
        @DisplayName("a holder that printed nothing measured nothing — no guess stands in for it")
        void unmeasured() {
            assertThat(ContainerRunner.CollectedOutput.measured(bounded, "", new ContainerRunner.OutputFile.Missing()))
                    .isEmpty();
            assertThat(ContainerRunner.CollectedOutput.measured(bounded,
                    DF.lines().limit(2).reduce("", (a, b) -> a + b + "\n").formatted(24, 1000, 3),
                    new ContainerRunner.OutputFile.Missing()))
                    .as("the bytes without the inodes")
                    .isEmpty();
            assertThat(ContainerRunner.CollectedOutput.measured(bounded, DF.replace("/repo/output", "/elsewhere")
                            .formatted(24, 1000, 3, 3, 4093), new ContainerRunner.OutputFile.Missing()))
                    .as("another mount's figures are not this directory's")
                    .isEmpty();
        }
    }
}
