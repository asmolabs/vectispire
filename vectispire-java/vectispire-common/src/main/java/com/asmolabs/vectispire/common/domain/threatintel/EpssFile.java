package com.asmolabs.vectispire.common.domain.threatintel;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;
import java.util.zip.GZIPInputStream;
import java.util.zip.ZipException;

/**
 * FIRST's daily EPSS file — every scored CVE with its probability and percentile — read as a
 * stream, and accepted only whole.
 *
 * <p><b>Why a file and not the API.</b> Each scan used to ask {@code api.first.org} for the scores
 * of the CVE it had just found, ninety at a time. That told a third party which vulnerabilities each
 * repository of the estate carried, on the day it was scanned — the inventory of what is exploitable
 * where, which is what this product exists to keep inside the organisation — and it did not work at
 * all on an estate without outbound access. The file carries every score for everybody; downloading
 * it says nothing about what is deployed, and a mirror can serve it inside a closed network.
 *
 * <p><b>Read whole, or not at all.</b> The file replaces the scores in use, so a partial one is
 * worse than none: every CVE it lost would read as unscored on the next scan. A gzip stream checks
 * its own length and CRC, so a download cut short is refused by the decompressor; a file that is
 * complete gzip but not the whole list — a mirror that exported half — is refused by its size
 * ({@link #MIN_ROWS}, and {@link #requireComparable} against the file in use). One malformed row
 * refuses the file: a score outside [0, 1] is not a probability, and silently skipping it would
 * make that CVE unscored without anybody being told.
 *
 * <p><b>Streamed, and bounded twice.</b> The file is some 380,000 rows and 12 MB once inflated;
 * nothing here holds more than one batch of it. The inflated size is counted as it is read
 * ({@link #MAX_INFLATED_BYTES}), so a small archive that inflates to gigabytes — a gzip bomb, or a
 * mirror serving the wrong thing — is refused at the ceiling rather than read into memory, and a
 * line longer than any row could be ({@link #MAX_LINE}) is refused before it is buffered.
 *
 * <p>The format, as FIRST publishes it:
 *
 * <pre>
 * #model_version:v2025.03.14,score_date:2026-09-27T12:00:21Z
 * cve,epss,percentile
 * CVE-1999-0001,0.03351,0.88245
 * </pre>
 */
public final class EpssFile {

    /**
     * FIRST's own address for the current file ({@code https://www.first.org/epss/data}). It answers
     * with a redirect to the day's dated file on the same host, which the download follows once.
     */
    public static final String DEFAULT_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz";

    /**
     * The fewest rows a whole file carries. FIRST scored some 200,000 CVE in 2023 and 380,000 in
     * September 2026, and the population only grows by the CVE published since: a file under this is
     * a truncated export, never a quiet year.
     */
    public static final long MIN_ROWS = 100_000;

    /**
     * The most rows accepted: five times today's population, and a bound on how long a
     * synchronisation writes. A file past it is not FIRST's.
     */
    public static final long MAX_ROWS = 2_000_000;

    /**
     * The share of the file in use a new one must carry at least. The population shrinks only when
     * CVE are rejected, a few hundred at a time; a file with a tenth fewer rows than yesterday's —
     * some 38,000 CVE — is an incomplete export, and applied it would leave every one of them
     * unscored on the next scan.
     */
    public static final double MIN_SHARE_OF_PREVIOUS = 0.9;

    /** The inflated file may weigh this much: ten times today's, and a gzip bomb's ceiling. */
    public static final long MAX_INFLATED_BYTES = 128L * 1024 * 1024;

    /** A row is some thirty characters; a line this long is not one. */
    static final int MAX_LINE = 256;

    /** The column the model version is stored in. */
    static final int VERSION_MAX = 32;

    private static final Pattern CVE = Pattern.compile("CVE-\\d{4}-\\d{4,}");
    private static final int GZIP_MAGIC_1 = 0x1f;
    private static final int GZIP_MAGIC_2 = 0x8b;

    private EpssFile() {}

    /**
     * What the file's first line says about it.
     *
     * @param modelVersion the model that produced the scores, {@code v2025.03.14} — scores of two
     *     models are not comparable, which is why it is shown beside them
     * @param scoreDate the day the scores are for: the age of the data, which the date of the sync
     *     does not give when a mirror is refreshed rarely
     */
    public record Header(String modelVersion, Instant scoreDate) {}

    /** One row: an upper-case CVE identifier, its probability and its percentile, both in [0, 1]. */
    public record Score(String cve, double score, double percentile) {}

    /**
     * What was read.
     *
     * @param rows the scores handed to the sink; zero when the sink stopped at the header
     * @param stopped whether the sink declined the file at its header — the same file as the one in
     *     use — in which case nothing past the header was read
     */
    public record Read(Header header, long rows, boolean stopped) {}

    /** Where the rows go, one batch at a time. */
    public interface Sink {
        /**
         * The header, before any row. Throw {@link Unreadable} to refuse the file — one older than
         * the file in use — or answer {@code false} to stop reading without refusing it.
         */
        boolean header(Header header);

        /** A batch of rows, in the file's order. Never empty. */
        void batch(List<Score> scores);
    }

    /** A file that is not FIRST's EPSS file, or not all of it. Never read as a file without scores. */
    public static final class Unreadable extends RuntimeException {

        private static final long serialVersionUID = 1L;

        public Unreadable(String reason) {
            super(reason);
        }

        public Unreadable(String reason, Throwable cause) {
            super(reason, cause);
        }
    }

    /**
     * Reads the file, gzip or plain — a mirror that serves it with {@code Content-Encoding: gzip}
     * reaches here already inflated by the HTTP client — and hands its rows to the sink.
     *
     * @throws Unreadable when it is not the whole file: see the class comment. The sink may have
     *     received batches by then; what it wrote is the caller's to discard
     */
    public static Read read(InputStream body, int batchSize, Sink sink) {
        if (batchSize < 1) {
            throw new IllegalArgumentException("batchSize must be positive");
        }
        try (InputStream in = inflated(body)) {
            return read(new Lines(in), batchSize, sink);
        } catch (ZipException | EOFException broken) {
            throw new Unreadable("the file is not a whole gzip archive (" + broken.getMessage()
                    + "): it was cut short or damaged", broken);
        } catch (IOException unreadable) {
            throw new Unreadable("the file could not be read: " + unreadable.getMessage(), unreadable);
        }
    }

    /**
     * Refuses a file markedly smaller than the one in use — see {@link #MIN_SHARE_OF_PREVIOUS}.
     *
     * @param previousRows the rows of the file in use; zero when there is none
     */
    public static void requireComparable(long previousRows, long rows) {
        if (previousRows > 0 && rows < previousRows * MIN_SHARE_OF_PREVIOUS) {
            throw new Unreadable("the file carries " + rows + " scores where the one in use carries " + previousRows
                    + ": an export that lost a tenth of the population is incomplete; kept the one in use");
        }
    }

    private static Read read(Lines lines, int batchSize, Sink sink) throws IOException {
        Header header = header(lines.next());
        String columns = lines.next();
        if (columns == null || !columns.trim().toLowerCase(Locale.ROOT).equals("cve,epss,percentile")) {
            throw new Unreadable("the second line is not the header \"cve,epss,percentile\": it is not the EPSS file");
        }
        if (!sink.header(header)) {
            return new Read(header, 0, true);
        }

        long rows = 0;
        List<Score> batch = new ArrayList<>(batchSize);
        for (String line = lines.next(); line != null; line = lines.next()) {
            if (line.isBlank()) {
                continue;
            }
            rows++;
            if (rows > MAX_ROWS) {
                throw new Unreadable("the file carries more than " + MAX_ROWS + " scores: it is not the EPSS file");
            }
            batch.add(row(line, lines.number()));
            if (batch.size() == batchSize) {
                sink.batch(List.copyOf(batch));
                batch.clear();
            }
        }
        if (!batch.isEmpty()) {
            sink.batch(List.copyOf(batch));
        }
        if (rows < MIN_ROWS) {
            throw new Unreadable("the file carries " + rows + " scores; a whole EPSS file carries more than "
                    + MIN_ROWS + ": it is incomplete");
        }
        return new Read(header, rows, false);
    }

    /** {@code #model_version:v2025.03.14,score_date:2026-09-27T12:00:21Z}: both are required. */
    private static Header header(String line) {
        if (line == null || !line.startsWith("#")) {
            throw new Unreadable("the file does not begin with its \"#model_version:…,score_date:…\" line: "
                    + "it is not the EPSS file, or is one too old to say which model scored it");
        }
        String version = null;
        Instant date = null;
        for (String pair : line.substring(1).split(",")) {
            int colon = pair.indexOf(':');
            if (colon < 0) {
                continue;
            }
            String key = pair.substring(0, colon).trim().toLowerCase(Locale.ROOT);
            String value = pair.substring(colon + 1).trim();
            switch (key) {
                case "model_version" -> version = value.isEmpty() ? null : value;
                case "score_date" -> date = instant(value);
                default -> {
                    // A field FIRST adds later is not a reason to refuse the file.
                }
            }
        }
        if (version == null) {
            throw new Unreadable("the file's first line names no model_version");
        }
        if (version.length() > VERSION_MAX) {
            throw new Unreadable("the file's model_version is longer than " + VERSION_MAX + " characters");
        }
        if (date == null) {
            // Refused rather than taken as today: the date is what tells a stale mirror from a fresh
            // file, and an invented one would make last month's scores look current.
            throw new Unreadable("the file's first line carries no readable score_date");
        }
        return new Header(version, date);
    }

    private static Instant instant(String value) {
        try {
            return Instant.parse(value);
        } catch (DateTimeParseException notAnInstant) {
            try {
                return LocalDate.parse(value).atStartOfDay(ZoneOffset.UTC).toInstant();
            } catch (DateTimeParseException notADay) {
                return null;
            }
        }
    }

    private static Score row(String line, long number) {
        String[] fields = line.split(",", -1);
        if (fields.length != 3) {
            throw new Unreadable("line " + number + " has " + fields.length + " fields where a row has three");
        }
        String cve = fields[0].trim().toUpperCase(Locale.ROOT);
        if (!CVE.matcher(cve).matches()) {
            throw new Unreadable("line " + number + " does not begin with a CVE identifier");
        }
        return new Score(cve, probability(fields[1], "epss", number), probability(fields[2], "percentile", number));
    }

    /**
     * A value in [0, 1], or a refusal. Never a default: an empty field read as zero would report a
     * measured "no chance of exploitation" for a CVE nobody scored.
     */
    private static double probability(String field, String column, long number) {
        double value;
        try {
            value = Double.parseDouble(field.trim());
        } catch (NumberFormatException notANumber) {
            throw new Unreadable("line " + number + ": the " + column + " is not a number");
        }
        if (!(value >= 0.0 && value <= 1.0)) {
            throw new Unreadable("line " + number + ": the " + column + " " + field.trim() + " is not within [0, 1]");
        }
        return value;
    }

    /** The body, inflated when it starts as gzip does, counted either way. */
    private static InputStream inflated(InputStream body) throws IOException {
        BufferedInputStream buffered = new BufferedInputStream(body);
        buffered.mark(2);
        int first = buffered.read();
        int second = buffered.read();
        buffered.reset();
        InputStream plain = first == GZIP_MAGIC_1 && second == GZIP_MAGIC_2
                ? new GZIPInputStream(buffered, 64 * 1024)
                : buffered;
        return new Ceiling(plain, MAX_INFLATED_BYTES);
    }

    /** Refuses to deliver more than its ceiling — counted after inflation, which is what memory sees. */
    private static final class Ceiling extends FilterInputStream {

        private final long max;
        private long count;

        Ceiling(InputStream in, long max) {
            super(in);
            this.max = max;
        }

        @Override
        public int read() throws IOException {
            int read = super.read();
            if (read >= 0) {
                counted(1);
            }
            return read;
        }

        @Override
        public int read(byte[] buffer, int offset, int length) throws IOException {
            int read = super.read(buffer, offset, length);
            if (read > 0) {
                counted(read);
            }
            return read;
        }

        private void counted(int bytes) {
            count += bytes;
            if (count > max) {
                throw new Unreadable("the file inflates past " + max + " bytes: it is not the EPSS file");
            }
        }
    }

    /** Lines of ASCII, none longer than {@link #MAX_LINE}; the line feed ends one, a carriage return is dropped. */
    private static final class Lines {

        private final InputStream in;
        private final ByteArrayOutputStream line = new ByteArrayOutputStream(64);
        private long number;

        Lines(InputStream in) {
            this.in = new BufferedInputStream(in, 64 * 1024);
        }

        /** The next line, or null at the end. */
        String next() throws IOException {
            line.reset();
            int read = in.read();
            if (read < 0) {
                return null;
            }
            number++;
            while (read >= 0 && read != '\n') {
                if (read != '\r') {
                    if (line.size() == MAX_LINE) {
                        throw new Unreadable("line " + number + " is longer than " + MAX_LINE
                                + " characters: it is not a row of the EPSS file");
                    }
                    line.write(read);
                }
                read = in.read();
            }
            return line.toString(StandardCharsets.US_ASCII);
        }

        long number() {
            return number;
        }
    }
}
