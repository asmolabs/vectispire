package com.asmolabs.vectispire.common.domain.reports;

import com.asmolabs.vectispire.common.domain.text.BoundedText;
import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * What a coverage report says about a whole repository: lines covered of lines counted, and
 * branches when the report counts them.
 *
 * <h2>Empty is refused, not recorded</h2>
 *
 * <p>A report over zero lines is neither 0 % nor 100 % covered: it measured nothing. Recorded, it
 * would be the newest figure a checklist reads — a pipeline whose coverage step broke would show
 * either a failure nobody caused or a success nobody earned. So a report with no line is refused in
 * words (decision 0007's rule, for a figure rather than a list). Branches are {@link Optional} for
 * the same reason: a report that counts none has not said "0 of 0", it has said nothing.
 *
 * <h2>Where each format keeps its totals</h2>
 *
 * <ul>
 *   <li><b>JaCoCo</b>: the {@code counter} elements that are direct children of {@code report} —
 *       the report's own totals, which JaCoCo writes only for a kind it counted.
 *   <li><b>Cobertura</b>: {@code lines-covered} and {@code lines-valid} on {@code coverage}, and the
 *       {@code branches-} pair. Every current writer (Cobertura 1.9+, coverage.py, gcovr, Istanbul,
 *       Coverlet) states them; a report without them is refused rather than recomputed from its
 *       {@code line} elements, which the writers also repeat under each method.
 *   <li><b>lcov</b>: the {@code DA} and {@code BRDA} records, merged across records naming the same
 *       file — a tracefile concatenated from several test runs lists a file once per run, and summing
 *       would count its lines twice. The {@code LF}/{@code LH} summaries are not trusted over the
 *       records they summarise.
 * </ul>
 *
 * <p>The bytes are the caller's ceiling; past it the report is refused unread.
 *
 * @param toolVersion the producer's version when the document states it — Cobertura's {@code version}
 *     attribute; JaCoCo's XML and lcov state none
 */
public record CoverageReport(CoverageFormat format, Counts lines, Optional<Counts> branches, Optional<String> toolVersion) {

    /** A tool version is display, and clipped to its column. */
    public static final int MAX_TOOL_VERSION = 100;

    /** Elements in one XML coverage report: far above what a 16 MB report can hold, below a flood. */
    static final long MAX_ELEMENTS = 4_000_000;

    /** lcov: the files, the line entries and branch entries across the whole tracefile. */
    static final int MAX_FILES = 200_000;
    static final int MAX_LINE_ENTRIES = 4_000_000;
    static final int MAX_BRANCH_ENTRIES = 1_000_000;
    static final int MAX_LINE_NUMBER = 10_000_000;
    static final int MAX_TEXT_LINE = 65_536;

    /** Covered of total, both counted by the report, never computed from a ratio it printed. */
    public record Counts(long covered, long total) {
        public Counts {
            if (covered < 0 || total < 0 || covered > total) {
                throw new InvalidReportException("The report counts " + covered + " covered of " + total
                        + "; a coverage count is non-negative and never more than its total.");
            }
        }
    }

    public CoverageReport {
        if (lines.total() == 0) {
            throw new InvalidReportException("The " + format.wireName() + " report counts no line: it measured "
                    + "nothing, which is neither 0 % nor 100 % covered, and it is not recorded.");
        }
        toolVersion = toolVersion.map(String::strip).filter(value -> !value.isEmpty())
                .map(value -> BoundedText.clip(value, MAX_TOOL_VERSION));
    }

    /**
     * Reads a report in the format the pipeline declared.
     *
     * @throws InvalidReportException past the ceiling, not the declared format, or empty
     */
    public static CoverageReport read(CoverageFormat format, byte[] document, long maxBytes) {
        if (document == null || document.length == 0) {
            throw new InvalidReportException("The coverage report is empty.");
        }
        if (document.length > maxBytes) {
            throw new InvalidReportException("The coverage report is larger than the " + maxBytes + " bytes accepted.");
        }
        return switch (format) {
            case JACOCO -> jacoco(document);
            case COBERTURA -> cobertura(document);
            case LCOV -> lcov(document);
        };
    }

    private static CoverageReport jacoco(byte[] document) {
        String what = "The JaCoCo report";
        Map<String, Counts> totals = new HashMap<>();
        SafeXml.read(new ByteArrayInputStream(document), what, new SafeXml.Budget(MAX_ELEMENTS), element -> {
            if (element.depth() == 1 && !"report".equals(element.name())) {
                throw new InvalidReportException(what + " opens with <" + element.name() + ">, not <report>: is it "
                        + "JaCoCo's XML report?");
            }
            if (element.depth() == 2 && "counter".equals(element.name())) {
                long missed = count(element, "missed", what);
                long covered = count(element, "covered", what);
                String type = element.attribute("type");
                if (type != null && totals.putIfAbsent(type, new Counts(covered, covered + missed)) != null) {
                    throw new InvalidReportException(what + " states its " + type + " total twice.");
                }
            }
        });
        Counts lines = totals.getOrDefault("LINE", new Counts(0, 0));
        Optional<Counts> branches = Optional.ofNullable(totals.get("BRANCH")).filter(counts -> counts.total() > 0);
        return new CoverageReport(CoverageFormat.JACOCO, lines, branches, Optional.empty());
    }

    private static CoverageReport cobertura(byte[] document) {
        String what = "The Cobertura report";
        Map<String, String> root = new LinkedHashMap<>();
        SafeXml.read(new ByteArrayInputStream(document), what, new SafeXml.Budget(MAX_ELEMENTS), element -> {
            if (element.depth() == 1) {
                if (!"coverage".equals(element.name())) {
                    throw new InvalidReportException(what + " opens with <" + element.name() + ">, not <coverage>: is "
                            + "it a Cobertura XML report?");
                }
                for (String name : new String[] {"lines-covered", "lines-valid", "branches-covered", "branches-valid",
                        "version"}) {
                    String value = element.attribute(name);
                    if (value != null) {
                        root.put(name, value);
                    }
                }
            }
        });
        if (!root.containsKey("lines-covered") || !root.containsKey("lines-valid")) {
            throw new InvalidReportException(what + " does not state lines-covered and lines-valid on <coverage>; "
                    + "the totals are read from there, never recomputed from a rate.");
        }
        Counts lines = new Counts(number(root.get("lines-covered"), "lines-covered", what),
                number(root.get("lines-valid"), "lines-valid", what));
        Optional<Counts> branches = Optional.empty();
        if (root.containsKey("branches-covered") && root.containsKey("branches-valid")) {
            branches = Optional.of(new Counts(number(root.get("branches-covered"), "branches-covered", what),
                            number(root.get("branches-valid"), "branches-valid", what)))
                    .filter(counts -> counts.total() > 0);
        }
        return new CoverageReport(CoverageFormat.COBERTURA, lines, branches, Optional.ofNullable(root.get("version")));
    }

    /**
     * An lcov tracefile. Lines are packed as {@code file << 32 | line} with the covered bit below,
     * sorted and merged, rather than held in a map: four million entries in a {@code long[]} are
     * 32 MB, in boxed map entries several times that, for an upload a pipeline may repeat.
     */
    private static CoverageReport lcov(byte[] document) {
        String text;
        try {
            text = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(document))
                    .toString();
        } catch (CharacterCodingException notText) {
            throw new InvalidReportException("The lcov tracefile is not UTF-8 text.");
        }

        Map<String, Integer> files = new HashMap<>();
        long[] lines = new long[1024];
        int lineCount = 0;
        Map<BranchKey, Boolean> branches = new HashMap<>();
        Integer file = null;
        boolean anyRecord = false;
        int number = 0;
        int start = 0;
        while (start < text.length()) {
            int end = text.indexOf('\n', start);
            if (end < 0) {
                end = text.length();
            }
            number++;
            if (end - start > MAX_TEXT_LINE) {
                throw new InvalidReportException("Line " + number + " of the lcov tracefile is longer than "
                        + MAX_TEXT_LINE + " characters.");
            }
            String line = text.substring(start, end).strip();
            start = end + 1;
            if (line.isEmpty()) {
                continue;
            }
            if (line.equals("end_of_record")) {
                if (file == null) {
                    throw lcovError(number, "end_of_record closes no SF record");
                }
                file = null;
                continue;
            }
            int colon = line.indexOf(':');
            if (colon <= 0 || !line.substring(0, colon).chars().allMatch(c -> c >= 'A' && c <= 'Z')) {
                throw lcovError(number, "is not an lcov record (\"KEY:value\")");
            }
            String key = line.substring(0, colon);
            String value = line.substring(colon + 1);
            switch (key) {
                case "SF" -> {
                    if (file != null) {
                        throw lcovError(number, "opens a record before the previous one's end_of_record");
                    }
                    if (value.isBlank()) {
                        throw lcovError(number, "names no source file");
                    }
                    if (!files.containsKey(value) && files.size() >= MAX_FILES) {
                        throw new InvalidReportException("The lcov tracefile names more than " + MAX_FILES + " files.");
                    }
                    file = files.computeIfAbsent(value, ignored -> files.size());
                    anyRecord = true;
                }
                case "DA" -> {
                    String[] parts = fields(value, 2, number, "DA:<line>,<hits>");
                    int at = lineNumber(parts[0], number);
                    long hits = signed(parts[1], number);
                    if (lineCount == MAX_LINE_ENTRIES) {
                        throw new InvalidReportException("The lcov tracefile holds more than " + MAX_LINE_ENTRIES
                                + " line entries.");
                    }
                    if (lineCount == lines.length) {
                        lines = Arrays.copyOf(lines, Math.min(MAX_LINE_ENTRIES, lines.length * 2));
                    }
                    lines[lineCount++] = ((((long) requireFile(file, number, key)) << 32 | at) << 1) | (hits > 0 ? 1 : 0);
                }
                case "BRDA" -> {
                    String[] parts = fields(value, 4, number, "BRDA:<line>,<block>,<branch>,<taken>");
                    int at = lineNumber(parts[0], number);
                    boolean taken = !parts[3].equals("-") && signed(parts[3], number) > 0;
                    BranchKey branch = new BranchKey(requireFile(file, number, key), at, parts[1], parts[2]);
                    if (!branches.containsKey(branch) && branches.size() >= MAX_BRANCH_ENTRIES) {
                        throw new InvalidReportException("The lcov tracefile holds more than " + MAX_BRANCH_ENTRIES
                                + " branch entries.");
                    }
                    branches.merge(branch, taken, Boolean::logicalOr);
                }
                default -> {
                    // TN, FN, FNDA, FNF, FNH, LF, LH, BRF, BRH, VER…: summaries and function data,
                    // not what the totals are read from.
                }
            }
        }
        if (file != null) {
            throw new InvalidReportException("The lcov tracefile ends inside a record, before its end_of_record: "
                    + "it was cut short.");
        }
        if (!anyRecord) {
            throw new InvalidReportException("The lcov tracefile holds no SF record: is it an lcov tracefile?");
        }

        long[] sorted = Arrays.copyOf(lines, lineCount);
        Arrays.sort(sorted);
        long total = 0;
        long covered = 0;
        for (int i = 0; i < sorted.length; ) {
            long entry = sorted[i] >>> 1;
            boolean hit = false;
            while (i < sorted.length && sorted[i] >>> 1 == entry) {
                hit |= (sorted[i] & 1) == 1;
                i++;
            }
            total++;
            if (hit) {
                covered++;
            }
        }
        long taken = branches.values().stream().filter(Boolean::booleanValue).count();
        Optional<Counts> branchCounts = branches.isEmpty()
                ? Optional.empty()
                : Optional.of(new Counts(taken, branches.size()));
        return new CoverageReport(CoverageFormat.LCOV, new Counts(covered, total), branchCounts, Optional.empty());
    }

    /** lcov 2 lets a block carry an exception marker and a branch an expression: kept as written. */
    private record BranchKey(int file, int line, String block, String branch) {}

    private static int requireFile(Integer file, int number, String key) {
        if (file == null) {
            throw lcovError(number, "gives " + key + " outside an SF record");
        }
        return file;
    }

    private static String[] fields(String value, int at, int number, String shape) {
        String[] parts = value.split(",", -1);
        if (parts.length < at) {
            throw lcovError(number, "is not " + shape);
        }
        return parts;
    }

    private static int lineNumber(String value, int number) {
        long line = signed(value, number);
        if (line < 1 || line > MAX_LINE_NUMBER) {
            throw lcovError(number, "names line " + BoundedText.clip(value, 20) + ", outside 1 to " + MAX_LINE_NUMBER);
        }
        return (int) line;
    }

    /**
     * A decimal integer, as lcov writes them; gcov's hit counts may exceed an {@code int}. Eighteen
     * digits at most, so {@link Long#parseLong} can never overflow into a 500.
     */
    private static long signed(String value, int number) {
        String digits = value.strip();
        boolean valid = !digits.isEmpty() && digits.length() <= 18;
        for (int i = 0; valid && i < digits.length(); i++) {
            char c = digits.charAt(i);
            valid = (c >= '0' && c <= '9') || (i == 0 && c == '-' && digits.length() > 1);
        }
        if (!valid) {
            throw lcovError(number, "carries \"" + BoundedText.clip(digits, 20) + "\" where a number is expected");
        }
        return Long.parseLong(digits);
    }

    private static InvalidReportException lcovError(int number, String problem) {
        return new InvalidReportException("Line " + number + " of the lcov tracefile " + problem + ".");
    }

    private static long count(SafeXml.Element element, String attribute, String what) {
        return number(element.attribute(attribute), attribute, what);
    }

    /** Eighteen digits at most: the sum of two stays a {@code long}, and parsing never overflows. */
    private static long number(String value, String attribute, String what) {
        String digits = value == null ? "" : value.strip();
        if (digits.isEmpty() || digits.length() > 18 || !digits.chars().allMatch(c -> c >= '0' && c <= '9')) {
            throw new InvalidReportException(what + " carries \"" + BoundedText.clip(digits, 20) + "\" as "
                    + attribute + ", where a count is expected.");
        }
        return Long.parseLong(digits);
    }
}
