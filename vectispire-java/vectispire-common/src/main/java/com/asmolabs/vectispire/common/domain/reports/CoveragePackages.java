package com.asmolabs.vectispire.common.domain.reports;

import com.asmolabs.vectispire.common.domain.reports.CoverageReport.Counts;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.TreeMap;

/**
 * What a coverage report counted per package, beside its totals — what a scoped {@code
 * coverage_threshold} rule reads (decision 0032, amendment of 2026-10-03).
 *
 * <h2>A package is a path</h2>
 *
 * <p>JaCoCo names its packages {@code org/example/service}, Cobertura {@code org.example.service}
 * (coverage.py {@code ledger.entries}, and {@code .} for the top level), lcov names files. All three
 * become one thing: a directory path, segments joined by {@code /}, no leading or trailing slash, the
 * top level the empty path. A JaCoCo or Cobertura package is its name with its dots read as slashes; an
 * lcov file is counted in the directory that holds it, as the tracefile spells it — absolute paths
 * included, which is why a scope's patterns are best written from {@code **}. One path per directory,
 * whatever the format, so a scope is written the same way over a Java report and a TypeScript one.
 *
 * <h2>Kept whole, or not at all — and saying which</h2>
 *
 * <p>The packages are kept when they can be kept honestly; otherwise the totals are still recorded and
 * the import says why its packages were not, which a scoped rule reports as no data in those words:
 *
 * <ul>
 *   <li>{@link State#TOO_MANY}: more than {@value #MAX_PACKAGES} packages. A tracefile naming 50,000
 *       files in as many directories would otherwise write 50,000 rows per upload, and a pipeline
 *       uploads at every commit. Never a truncated list: a scope over the first ten thousand would
 *       measure a part of the report as if it were the scope.
 *   <li>{@link State#PATH_REFUSED}: a path longer than {@value #MAX_PATH} characters, or carrying a
 *       control character — never clipped, since two clipped paths could become one.
 *   <li>{@link State#INCONSISTENT}: the packages do not add up to the report's totals, or a count under
 *       them does not read. The totals are what the unscoped rule has always judged; a scoped figure
 *       computed from parts that disagree with them would be a second, contradicting statement of the
 *       same report.
 * </ul>
 *
 * <p>Refusing the whole import instead would refuse reports the product accepted before packages were
 * kept, for a reason that concerns only the scoped rules.
 *
 * @param packages sorted by path, each counting at least one line or branch; empty unless {@link
 *     State#KEPT}
 */
public record CoveragePackages(State state, List<Package> packages) {

    /** Above any real project's package count, well below a flood a pipeline repeats at every commit. */
    public static final int MAX_PACKAGES = 10_000;

    /** The column's bound: a path is never clipped, so a longer one keeps no package at all. */
    public static final int MAX_PATH = 1_000;

    /** Why the packages were kept or not — stored with the import as {@link #wireName()}. */
    public enum State {
        KEPT,
        TOO_MANY,
        PATH_REFUSED,
        INCONSISTENT;

        public String wireName() {
            return name().toLowerCase(Locale.ROOT);
        }

        public static Optional<State> ofStored(String value) {
            return Arrays.stream(values()).filter(state -> state.wireName().equals(value)).findFirst();
        }

        /** Why a report's packages were not kept, as a measurement's evidence words it. */
        public String why() {
            return switch (this) {
                case KEPT -> "its packages were kept";
                case TOO_MANY -> "the report names more than " + MAX_PACKAGES + " packages, and the counts of none "
                        + "of them were kept";
                case PATH_REFUSED -> "a package path in the report is longer than " + MAX_PATH
                        + " characters or carries a control character, and the counts of no package were kept";
                case INCONSISTENT -> "the report's per-package counts do not add up to its totals, and were not kept";
            };
        }
    }

    /** @param branches empty when the report counted no branch at all, as its totals' */
    public record Package(String path, Counts lines, Optional<Counts> branches) {

        public Package {
            Objects.requireNonNull(path, "path");
            Objects.requireNonNull(lines, "lines");
            Objects.requireNonNull(branches, "branches");
        }
    }

    public CoveragePackages {
        Objects.requireNonNull(state, "state");
        packages = List.copyOf(packages);
        if ((state == State.KEPT) == packages.isEmpty()) {
            throw new IllegalArgumentException("Packages are listed when kept, and only then.");
        }
    }

    /**
     * A package's or a directory's name as a path: backslashes and — for the formats that dot their
     * packages — dots read as slashes, empty and {@code .} segments dropped.
     */
    static String path(String raw, boolean dotted) {
        String value = raw == null ? "" : raw.replace('\\', '/');
        if (dotted) {
            value = value.replace('.', '/');
        }
        List<String> segments = new ArrayList<>();
        for (String segment : value.split("/", -1)) {
            if (!segment.isEmpty() && !segment.equals(".")) {
                segments.add(segment);
            }
        }
        return String.join("/", segments);
    }

    /** The directory holding an lcov source file, as a path. */
    static String directoryOf(String file) {
        String path = path(file, false);
        int slash = path.lastIndexOf('/');
        return slash < 0 ? "" : path.substring(0, slash);
    }

    /** What a reader adds up as it walks a report, then checks against the report's totals. */
    static final class Tally {

        private final Map<String, long[]> sums = new TreeMap<>();
        private State refused;

        /** One more package's — or file's, or line's — counts, its path already read as one. */
        void add(String path, long linesCovered, long linesTotal, long branchesCovered, long branchesTotal) {
            if (refused != null) {
                return;
            }
            if (path.length() > MAX_PATH || path.chars().anyMatch(Character::isISOControl)) {
                refuse(State.PATH_REFUSED);
                return;
            }
            long[] sum = sums.get(path);
            if (sum == null) {
                if (sums.size() == MAX_PACKAGES) {
                    refuse(State.TOO_MANY);
                    return;
                }
                sum = new long[4];
                sums.put(path, sum);
            }
            try {
                sum[0] = Math.addExact(sum[0], linesCovered);
                sum[1] = Math.addExact(sum[1], linesTotal);
                sum[2] = Math.addExact(sum[2], branchesCovered);
                sum[3] = Math.addExact(sum[3], branchesTotal);
            } catch (ArithmeticException overflow) {
                refuse(State.INCONSISTENT);
            }
        }

        /** A count under a package did not read: the packages cannot be told to add up. */
        void unreadable() {
            refuse(State.INCONSISTENT);
        }

        private void refuse(State state) {
            if (refused == null) {
                refused = state;
                sums.clear();
            }
        }

        CoveragePackages finish(Counts lines, Optional<Counts> branches) {
            if (refused != null) {
                return new CoveragePackages(refused, List.of());
            }
            List<Package> packages = new ArrayList<>();
            long linesCovered = 0;
            long linesTotal = 0;
            long branchesCovered = 0;
            long branchesTotal = 0;
            try {
                for (Map.Entry<String, long[]> entry : sums.entrySet()) {
                    long[] sum = entry.getValue();
                    linesCovered = Math.addExact(linesCovered, sum[0]);
                    linesTotal = Math.addExact(linesTotal, sum[1]);
                    branchesCovered = Math.addExact(branchesCovered, sum[2]);
                    branchesTotal = Math.addExact(branchesTotal, sum[3]);
                    if (sum[1] == 0 && sum[3] == 0) {
                        continue; // counts nothing: no scope gains or loses anything by it
                    }
                    if (sum[0] > sum[1] || sum[2] > sum[3]) {
                        return new CoveragePackages(State.INCONSISTENT, List.of());
                    }
                    packages.add(new Package(entry.getKey(), new Counts(sum[0], sum[1]),
                            branches.map(ignored -> new Counts(sum[2], sum[3]))));
                }
            } catch (ArithmeticException overflow) {
                return new CoveragePackages(State.INCONSISTENT, List.of());
            }
            boolean linesAgree = linesCovered == lines.covered() && linesTotal == lines.total();
            boolean branchesAgree = branches.isEmpty()
                    || (branches.get().covered() == branchesCovered && branches.get().total() == branchesTotal);
            if (!linesAgree || !branchesAgree || packages.isEmpty()) {
                return new CoveragePackages(State.INCONSISTENT, List.of());
            }
            return new CoveragePackages(State.KEPT, packages);
        }
    }
}
