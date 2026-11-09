package com.asmolabs.vectispire.common.domain.threatintel;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.zip.GZIPOutputStream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("FIRST's daily EPSS file, read whole or not at all")
class EpssFileTest {

    private static final String HEADER = "#model_version:v2025.03.14,score_date:2026-09-27T12:00:21Z\n"
            + "cve,epss,percentile\n";
    private static final int WHOLE = (int) EpssFile.MIN_ROWS + 5;

    @Test
    @DisplayName("reads the header and every row, in batches, in the file's order")
    void readsAWholeFile() {
        Collected sink = new Collected();

        EpssFile.Read read = EpssFile.read(new ByteArrayInputStream(gzip(file(WHOLE))), 1000, sink);

        assertThat(read.stopped()).isFalse();
        assertThat(read.rows()).isEqualTo(WHOLE);
        assertThat(read.header()).isEqualTo(new EpssFile.Header("v2025.03.14", Instant.parse("2026-09-27T12:00:21Z")));
        assertThat(sink.header).isEqualTo(read.header());
        assertThat(sink.rows).hasSize(WHOLE);
        assertThat(sink.batches).isEqualTo(101);
        assertThat(sink.rows.get(0)).isEqualTo(new EpssFile.Score("CVE-2020-0000", 0.0, 0.0));
        assertThat(sink.rows.get(7)).isEqualTo(new EpssFile.Score("CVE-2020-0007", 0.00007, 0.00007));
    }

    @Test
    @DisplayName("a file served already inflated is read as it is")
    void readsPlainCsv() {
        // A mirror answering with Content-Encoding: gzip reaches the reader inflated by the client.
        EpssFile.Read read = EpssFile.read(new ByteArrayInputStream(file(WHOLE).getBytes(StandardCharsets.US_ASCII)),
                5000, new Collected());

        assertThat(read.rows()).isEqualTo(WHOLE);
    }

    @Test
    @DisplayName("a download cut short is refused by the archive's own length and checksum")
    void truncatedGzipIsRefused() {
        byte[] whole = gzip(file(WHOLE));
        byte[] cut = Arrays.copyOf(whole, whole.length - 100);

        assertThatThrownBy(() -> EpssFile.read(new ByteArrayInputStream(cut), 1000, new Collected()))
                .isInstanceOf(EpssFile.Unreadable.class)
                .hasMessageContaining("cut short");
    }

    @Test
    @DisplayName("a whole archive of part of the file is refused by its size")
    void tooFewRowsIsRefused() {
        assertThatThrownBy(() -> EpssFile.read(new ByteArrayInputStream(gzip(file(90_000))), 1000, new Collected()))
                .isInstanceOf(EpssFile.Unreadable.class)
                .hasMessageContaining("carries 90000 scores")
                .hasMessageContaining("incomplete");
    }

    @Test
    @DisplayName("a file without its model line, or without the column header, is not the EPSS file")
    void badHeadersAreRefused() {
        String rows = file(WHOLE).substring(HEADER.length());
        assertThatThrownBy(() -> read("cve,epss,percentile\n" + rows))
                .isInstanceOf(EpssFile.Unreadable.class)
                .hasMessageContaining("#model_version");
        assertThatThrownBy(() -> read("#model_version:v2025.03.14,score_date:2026-09-27T12:00:21Z\ncve,score\n" + rows))
                .isInstanceOf(EpssFile.Unreadable.class)
                .hasMessageContaining("cve,epss,percentile");
        assertThatThrownBy(() -> read("#model_version:v2025.03.14\ncve,epss,percentile\n" + rows))
                .isInstanceOf(EpssFile.Unreadable.class)
                .hasMessageContaining("score_date");
        assertThatThrownBy(() -> read("#model_version:v2025.03.14,score_date:yesterday\ncve,epss,percentile\n" + rows))
                .isInstanceOf(EpssFile.Unreadable.class)
                .hasMessageContaining("score_date");
        assertThatThrownBy(() -> read("#score_date:2026-09-27T12:00:21Z\ncve,epss,percentile\n" + rows))
                .isInstanceOf(EpssFile.Unreadable.class)
                .hasMessageContaining("model_version");
    }

    @Test
    @DisplayName("a score outside [0, 1], or not a number, refuses the file rather than the row")
    void outOfRangeScoresAreRefused() {
        for (String bad : List.of("1.2", "-0.01", "NaN", "", "0,5")) {
            String file = file(WHOLE).replace("CVE-2020-0003,0.00003,", "CVE-2020-0003," + bad + ",");
            assertThatThrownBy(() -> read(file)).as(bad)
                    .isInstanceOf(EpssFile.Unreadable.class)
                    .hasMessageContaining("line 6");
        }
        String percentile = file(WHOLE).replace("CVE-2020-0003,0.00003,0.00003", "CVE-2020-0003,0.00003,1.5");
        assertThatThrownBy(() -> read(percentile))
                .isInstanceOf(EpssFile.Unreadable.class)
                .hasMessageContaining("percentile 1.5 is not within [0, 1]");
        String notACve = file(WHOLE).replace("CVE-2020-0003,", "GHSA-xxxx,");
        assertThatThrownBy(() -> read(notACve))
                .isInstanceOf(EpssFile.Unreadable.class)
                .hasMessageContaining("CVE identifier");
    }

    @Test
    @DisplayName("a gzip bomb is refused at the inflated ceiling, not read into memory")
    void aGzipBombIsRefused() {
        // A small archive of a valid beginning followed by 130 MiB of blank lines, which the reader
        // skips: only the ceiling on inflated bytes stops it.
        byte[] bomb;
        ByteArrayOutputStream compressed = new ByteArrayOutputStream();
        try (GZIPOutputStream gzip = new GZIPOutputStream(compressed)) {
            gzip.write(file(10).getBytes(StandardCharsets.US_ASCII));
            byte[] blank = new byte[1024 * 1024];
            Arrays.fill(blank, (byte) '\n');
            for (int megabyte = 0; megabyte < 130; megabyte++) {
                gzip.write(blank);
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        bomb = compressed.toByteArray();
        assertThat(bomb.length).as("the archive is small").isLessThan(1024 * 1024);

        assertThatThrownBy(() -> EpssFile.read(new ByteArrayInputStream(bomb), 1000, new Collected()))
                .isInstanceOf(EpssFile.Unreadable.class)
                .hasMessageContaining("inflates past " + EpssFile.MAX_INFLATED_BYTES);
    }

    @Test
    @DisplayName("a line longer than any row is refused before it is buffered")
    void aLongLineIsRefused() {
        String file = HEADER + "CVE-2020-0001," + "1".repeat(10_000) + ",0.5\n";

        assertThatThrownBy(() -> read(file))
                .isInstanceOf(EpssFile.Unreadable.class)
                .hasMessageContaining("longer than");
    }

    @Test
    @DisplayName("the sink sees the header before any row, and may stop there or refuse the file")
    void theSinkDecidesAtTheHeader() {
        Collected stopping = new Collected();
        stopping.proceed = false;

        EpssFile.Read read = EpssFile.read(new ByteArrayInputStream(gzip(file(WHOLE))), 1000, stopping);

        assertThat(read.stopped()).isTrue();
        assertThat(read.rows()).isZero();
        assertThat(stopping.rows).isEmpty();

        EpssFile.Sink refusing = new EpssFile.Sink() {
            @Override
            public boolean header(EpssFile.Header header) {
                throw new EpssFile.Unreadable("older than the one in use");
            }

            @Override
            public void batch(List<EpssFile.Score> scores) {
                throw new AssertionError("no row after a refused header");
            }
        };
        assertThatThrownBy(() -> EpssFile.read(new ByteArrayInputStream(gzip(file(WHOLE))), 1000, refusing))
                .hasMessage("older than the one in use");
    }

    @Test
    @DisplayName("a file with a tenth fewer rows than the one in use is refused; the first one is not compared")
    void comparedWithTheFileInUse() {
        EpssFile.requireComparable(0, 150_000);
        EpssFile.requireComparable(380_000, 342_000);
        EpssFile.requireComparable(380_000, 400_000);

        assertThatThrownBy(() -> EpssFile.requireComparable(380_000, 341_999))
                .isInstanceOf(EpssFile.Unreadable.class)
                .hasMessageContaining("incomplete");
    }

    private static void read(String file) {
        EpssFile.read(new ByteArrayInputStream(gzip(file)), 1000, new Collected());
    }

    /** A file of {@code rows} rows, CVE-2020-0000 onwards, each scored its number over 100,000. */
    static String file(int rows) {
        StringBuilder file = new StringBuilder(HEADER);
        for (int row = 0; row < rows; row++) {
            String score = String.format(Locale.ROOT, "%.5f", row / 100_000.0 % 1.0);
            file.append(String.format(Locale.ROOT, "CVE-2020-%04d,%s,%s\n", row, score, score));
        }
        return file.toString();
    }

    static byte[] gzip(String text) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (GZIPOutputStream gzip = new GZIPOutputStream(out)) {
            gzip.write(text.getBytes(StandardCharsets.US_ASCII));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return out.toByteArray();
    }

    private static final class Collected implements EpssFile.Sink {
        EpssFile.Header header;
        final List<EpssFile.Score> rows = new ArrayList<>();
        int batches;
        boolean proceed = true;

        @Override
        public boolean header(EpssFile.Header header) {
            this.header = header;
            return proceed;
        }

        @Override
        public void batch(List<EpssFile.Score> scores) {
            assertThat(scores).isNotEmpty();
            batches++;
            rows.addAll(scores);
        }
    }
}
