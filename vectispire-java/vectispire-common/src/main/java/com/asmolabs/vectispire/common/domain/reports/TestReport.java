package com.asmolabs.vectispire.common.domain.reports;

import com.asmolabs.vectispire.common.domain.text.BoundedText;
import java.io.ByteArrayInputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Locale;
import java.util.zip.ZipEntry;
import java.util.zip.ZipException;
import java.util.zip.ZipInputStream;

/**
 * What a JUnit test report says, per suite: how many tests ran, failed, errored, were skipped.
 *
 * <h2>Counted from the test cases, not from the suite's attributes</h2>
 *
 * <p>The {@code tests}, {@code failures}, {@code errors} and {@code skipped} attributes are a
 * summary each producer writes its own way — some omit {@code skipped}, some say {@code disabled},
 * a {@code testsuites} root repeats its nested suites' totals — and a summary that disagrees with the
 * cases it summarises is exactly the report nobody notices. So each {@code testcase} is counted into
 * the innermost {@code testsuite} around it: an {@code error} child makes it an error, a {@code
 * failure} a failure, a {@code skipped} a skip, and none a pass. Surefire's {@code flakyFailure} and
 * {@code rerunFailure} are the attempts before a pass, and count as nothing. A suite that holds no
 * case of its own — a container of suites — is not listed.
 *
 * <h2>Empty is refused, not recorded</h2>
 *
 * <p>A report with no test case is not a passing suite, it is a pipeline whose test step ran
 * nothing — or whose report path matched nothing. Recorded, it would be the newest report a
 * checklist reads, with no failure in it (decision 0007). It is refused in words.
 *
 * <h2>A zip, and its guards</h2>
 *
 * <p>At most {@value #MAX_ENTRIES} entries; each inflated to at most {@value #MAX_ENTRY_BYTES} bytes
 * and all of them to {@value #MAX_INFLATED_BYTES}, counted as the bytes come out of the inflater and
 * never taken from the headers, which the archive's author wrote; an archive inside the archive is
 * refused, not opened. Only the {@code .xml} entries are read — Surefire writes a {@code .txt} beside
 * each — and every one of them must be a JUnit document; the others are inflated through the same
 * counter and discarded, since skipping an entry inflates it all the same. Nothing is written to disk, so an entry's
 * path is a name and nothing more.
 */
public record TestReport(TestReportFormat format, int documents, List<Suite> suites) {

    public static final int MAX_SUITE_NAME = 500;
    static final int MAX_ENTRIES = 5_000;
    static final long MAX_ENTRY_BYTES = 32L * 1024 * 1024;
    static final long MAX_INFLATED_BYTES = 256L * 1024 * 1024;
    static final int MAX_SUITES = 20_000;
    static final int MAX_TESTS = 1_000_000;
    static final long MAX_ELEMENTS = 8_000_000;

    /** One suite's counts; {@code tests} includes the failed, errored and skipped ones. */
    public record Suite(String name, int tests, int failures, int errors, int skipped) {}

    public TestReport {
        suites = List.copyOf(suites);
        if (suites.isEmpty()) {
            throw new InvalidReportException("The test report holds no test case: a report of nothing is not a "
                    + "passing suite, and it is not recorded.");
        }
    }

    public int tests() {
        return suites.stream().mapToInt(Suite::tests).sum();
    }

    public int failures() {
        return suites.stream().mapToInt(Suite::failures).sum();
    }

    public int errors() {
        return suites.stream().mapToInt(Suite::errors).sum();
    }

    public int skipped() {
        return suites.stream().mapToInt(Suite::skipped).sum();
    }

    /**
     * Reads a report in the form the pipeline declared.
     *
     * @throws InvalidReportException past the ceiling, not JUnit, a zip past its guards, or empty
     */
    public static TestReport read(TestReportFormat format, byte[] document, long maxBytes) {
        if (document == null || document.length == 0) {
            throw new InvalidReportException("The test report is empty.");
        }
        if (document.length > maxBytes) {
            throw new InvalidReportException("The test report is larger than the " + maxBytes + " bytes accepted.");
        }
        Collector collector = new Collector();
        SafeXml.Budget budget = new SafeXml.Budget(MAX_ELEMENTS);
        int documents = switch (format) {
            case JUNIT_XML -> {
                collector.document(new ByteArrayInputStream(document), "The JUnit report", budget);
                yield 1;
            }
            case JUNIT_ZIP -> zip(document, collector, budget);
        };
        return new TestReport(format, documents, collector.suites);
    }

    private static int zip(byte[] archive, Collector collector, SafeXml.Budget budget) {
        int entries = 0;
        int documents = 0;
        long[] inflated = {0};
        try (ZipInputStream zip = new ZipInputStream(new ByteArrayInputStream(archive))) {
            ZipEntry entry;
            while ((entry = zip.getNextEntry()) != null) {
                if (++entries > MAX_ENTRIES) {
                    throw new InvalidReportException("The zip holds more than " + MAX_ENTRIES + " entries.");
                }
                String name = BoundedText.clip(entry.getName(), 200);
                String lower = name.toLowerCase(Locale.ROOT);
                if (lower.endsWith(".zip") || lower.endsWith(".jar") || lower.endsWith(".gz") || lower.endsWith(".tar")) {
                    throw new InvalidReportException("Entry " + name + " is an archive inside the archive; nested "
                            + "archives are not opened.");
                }
                if (entry.isDirectory()) {
                    continue;
                }
                Bounded bytes = new Bounded(zip, name, inflated);
                if (!lower.endsWith(".xml")) {
                    // Drained through the counter rather than left to getNextEntry, which would
                    // inflate it to skip it with nothing counting: a bomb named .txt is still one.
                    bytes.transferTo(OutputStream.nullOutputStream());
                    continue;
                }
                if (bytes.startsLikeAnArchive()) {
                    throw new InvalidReportException("Entry " + name + " is an archive inside the archive; nested "
                            + "archives are not opened.");
                }
                collector.document(bytes, "Entry " + name, budget);
                documents++;
            }
        } catch (ZipException malformed) {
            throw new InvalidReportException("The body is not a readable zip archive.");
        } catch (IOException unreadable) {
            throw new InvalidReportException("The zip archive could not be read to its end.");
        }
        if (entries == 0) {
            throw new InvalidReportException("The body is not a zip archive, or an empty one.");
        }
        if (documents == 0) {
            throw new InvalidReportException("The zip holds no .xml entry: no JUnit report was found in it.");
        }
        return documents;
    }

    /** The suites of every document, in the order they were read. */
    private static final class Collector {
        private final List<Suite> suites = new ArrayList<>();
        private int tests;

        void document(InputStream input, String what, SafeXml.Budget budget) {
            Deque<Open> open = new ArrayDeque<>();
            int[] caseDepth = {0};
            String[] outcome = {null};
            SafeXml.read(input, what, budget, new SafeXml.Handler() {
                @Override
                public void start(SafeXml.Element element) {
                    if (element.depth() == 1 && !"testsuites".equals(element.name()) && !"testsuite".equals(element.name())) {
                        throw new InvalidReportException(what + " opens with <" + element.name() + ">, not <testsuites> "
                                + "or <testsuite>: is it a JUnit XML report?");
                    }
                    switch (element.name()) {
                        case "testsuite" -> {
                            if (caseDepth[0] != 0) {
                                throw new InvalidReportException(what + " nests a testsuite inside a testcase.");
                            }
                            String name = element.attribute("name");
                            if (name == null || name.isBlank()) {
                                throw new InvalidReportException(what + " has a testsuite without a name; a suite is "
                                        + "matched by its name, and an unnamed one could only be matched by accident.");
                            }
                            open.push(new Open(BoundedText.clip(name.strip(), MAX_SUITE_NAME)));
                        }
                        case "testcase" -> {
                            if (open.isEmpty()) {
                                throw new InvalidReportException(what + " has a testcase outside any testsuite.");
                            }
                            caseDepth[0] = element.depth();
                            outcome[0] = null;
                        }
                        case "error", "failure", "skipped" -> {
                            if (caseDepth[0] != 0 && element.depth() == caseDepth[0] + 1) {
                                outcome[0] = worse(outcome[0], element.name());
                            }
                        }
                        default -> {
                            // properties, system-out, flakyFailure…: nothing counted.
                        }
                    }
                }

                @Override
                public void end(String name, int depth) {
                    if ("testcase".equals(name) && depth == caseDepth[0]) {
                        caseDepth[0] = 0;
                        if (++tests > MAX_TESTS) {
                            throw new InvalidReportException("The test report holds more than " + MAX_TESTS + " test cases.");
                        }
                        open.peek().count(outcome[0]);
                    } else if ("testsuite".equals(name) && caseDepth[0] == 0) {
                        Open suite = open.pop();
                        if (suite.tests > 0) {
                            if (suites.size() == MAX_SUITES) {
                                throw new InvalidReportException("The test report holds more than " + MAX_SUITES
                                        + " suites.");
                            }
                            suites.add(new Suite(suite.name, suite.tests, suite.failures, suite.errors, suite.skipped));
                        }
                    }
                }
            });
        }

        /** An error outweighs a failure, which outweighs a skip: a case is counted once. */
        private static String worse(String current, String next) {
            if (current == null) {
                return next;
            }
            return rank(next) > rank(current) ? next : current;
        }

        private static int rank(String outcome) {
            return switch (outcome) {
                case "error" -> 3;
                case "failure" -> 2;
                default -> 1;
            };
        }
    }

    private static final class Open {
        private final String name;
        private int tests;
        private int failures;
        private int errors;
        private int skipped;

        Open(String name) {
            this.name = name;
        }

        void count(String outcome) {
            tests++;
            if (outcome == null) {
                return;
            }
            switch (outcome) {
                case "error" -> errors++;
                case "failure" -> failures++;
                default -> skipped++;
            }
        }
    }

    /**
     * One entry's inflated bytes, counted against the entry's ceiling and the archive's as they are
     * read — a declared size is the archive author's claim, and a zip bomb's is a lie. Never closes
     * the archive under it: the next entry is read from the same stream.
     */
    private static final class Bounded extends FilterInputStream {
        private final String name;
        private final long[] inflated;
        private long read;
        private final byte[] head = new byte[4];
        private int headLength;
        private int headPosition;

        Bounded(InputStream zip, String name, long[] inflated) throws IOException {
            super(zip);
            this.name = name;
            this.inflated = inflated;
            while (headLength < head.length) {
                int n = in.read(head, headLength, head.length - headLength);
                if (n < 0) {
                    break;
                }
                headLength += n;
            }
            spend(headLength);
        }

        /** A local file header's signature, {@code PK\3\4}: whatever the entry's name, it is a zip. */
        boolean startsLikeAnArchive() {
            return headLength == 4 && head[0] == 'P' && head[1] == 'K' && head[2] == 3 && head[3] == 4;
        }

        @Override
        public int read() throws IOException {
            if (headPosition < headLength) {
                return head[headPosition++] & 0xff;
            }
            int value = in.read();
            if (value >= 0) {
                spend(1);
            }
            return value;
        }

        @Override
        public int read(byte[] buffer, int offset, int length) throws IOException {
            if (length == 0) {
                return 0;
            }
            if (headPosition < headLength) {
                int n = Math.min(length, headLength - headPosition);
                System.arraycopy(head, headPosition, buffer, offset, n);
                headPosition += n;
                return n;
            }
            int n = in.read(buffer, offset, length);
            if (n > 0) {
                spend(n);
            }
            return n;
        }

        @Override
        public long skip(long n) throws IOException {
            byte[] discard = new byte[(int) Math.min(n, 8192)];
            int skipped = read(discard, 0, discard.length);
            return Math.max(skipped, 0);
        }

        @Override
        public void close() {
            // The archive stays open: its next entry is read from the same stream.
        }

        private void spend(long n) {
            read += n;
            inflated[0] += n;
            if (read > MAX_ENTRY_BYTES) {
                throw new InvalidReportException("Entry " + name + " inflates past " + MAX_ENTRY_BYTES + " bytes.");
            }
            if (inflated[0] > MAX_INFLATED_BYTES) {
                throw new InvalidReportException("The zip inflates past " + MAX_INFLATED_BYTES + " bytes.");
            }
        }
    }
}
