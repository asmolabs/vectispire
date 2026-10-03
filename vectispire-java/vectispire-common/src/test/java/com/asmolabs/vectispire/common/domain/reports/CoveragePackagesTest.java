package com.asmolabs.vectispire.common.domain.reports;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.reports.CoveragePackages.Package;
import com.asmolabs.vectispire.common.domain.reports.CoveragePackages.State;
import com.asmolabs.vectispire.common.domain.reports.CoverageReport.Counts;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * The counts per package each reader keeps beside the totals: what they are on invented reports written
 * the way each tool writes them, that they always add up to the totals, and what happens — said, never
 * truncated — when they cannot be kept.
 */
@DisplayName("a coverage report's packages")
class CoveragePackagesTest {

    private static final long CAP = 16L * 1024 * 1024;

    private static CoverageReport read(CoverageFormat format, String document) {
        return CoverageReport.read(format, document.getBytes(StandardCharsets.UTF_8), CAP);
    }

    private static CoverageReport sample(CoverageFormat format, String name) {
        return CoverageReport.read(format, CoverageReportTest.sample(name), CAP);
    }

    /** The totals are the sum of the parts, lines and branches both — the rule every kept report obeys. */
    private static void addsUp(CoverageReport report) {
        assertThat(report.packages().state()).isEqualTo(State.KEPT);
        long linesCovered = report.packages().packages().stream().mapToLong(part -> part.lines().covered()).sum();
        long linesTotal = report.packages().packages().stream().mapToLong(part -> part.lines().total()).sum();
        assertThat(new Counts(linesCovered, linesTotal)).isEqualTo(report.lines());
        report.branches().ifPresentOrElse(branches -> {
            long covered = report.packages().packages().stream().mapToLong(part -> part.branches().orElseThrow().covered()).sum();
            long total = report.packages().packages().stream().mapToLong(part -> part.branches().orElseThrow().total()).sum();
            assertThat(new Counts(covered, total)).isEqualTo(branches);
        }, () -> assertThat(report.packages().packages()).allSatisfy(part -> assertThat(part.branches()).isEmpty()));
    }

    @Nested
    @DisplayName("JaCoCo")
    class Jacoco {

        @Test
        @DisplayName("keeps each package's own LINE and BRANCH counters, its name read as a path")
        void packages() {
            CoverageReport report = sample(CoverageFormat.JACOCO, "jacoco.xml");

            assertThat(report.packages().packages()).containsExactly(
                    new Package("com/example/invoicing", new Counts(7, 9), Optional.of(new Counts(3, 4))),
                    new Package("com/example/tax", new Counts(0, 3), Optional.of(new Counts(0, 0))));
            addsUp(report);
        }

        @Test
        @DisplayName("an aggregate report's groups: a package under two modules is one path, summed")
        void groups() {
            CoverageReport report = sample(CoverageFormat.JACOCO, "jacoco-groups.xml");

            assertThat(report.packages().packages()).containsExactly(
                    new Package("org/example/orders/generated", new Counts(0, 30), Optional.of(new Counts(0, 0))),
                    new Package("org/example/orders/service", new Counts(9, 12), Optional.of(new Counts(3, 4))),
                    new Package("org/example/orders/web", new Counts(5, 5), Optional.of(new Counts(1, 2))));
            addsUp(report);
        }

        @Test
        @DisplayName("packages that do not add up to the report's totals are not kept, and the totals still are")
        void inconsistent() {
            CoverageReport report = read(CoverageFormat.JACOCO, "<report name=\"r\"><package name=\"a/b\">"
                    + "<counter type=\"LINE\" missed=\"1\" covered=\"1\"/></package>"
                    + "<counter type=\"LINE\" missed=\"5\" covered=\"5\"/></report>");

            assertThat(report.lines()).isEqualTo(new Counts(5, 10));
            assertThat(report.packages()).isEqualTo(new CoveragePackages(State.INCONSISTENT, java.util.List.of()));
        }

        @Test
        @DisplayName("lines that add up are not enough: branches that do not keep no package either")
        void branchesInconsistent() {
            CoverageReport report = read(CoverageFormat.JACOCO, "<report name=\"r\"><package name=\"a/b\">"
                    + "<counter type=\"LINE\" missed=\"1\" covered=\"1\"/><counter type=\"BRANCH\" missed=\"1\" covered=\"1\"/>"
                    + "</package><counter type=\"LINE\" missed=\"1\" covered=\"1\"/>"
                    + "<counter type=\"BRANCH\" missed=\"2\" covered=\"2\"/></report>");

            assertThat(report.packages().state()).isEqualTo(State.INCONSISTENT);
        }

        @Test
        @DisplayName("a report without branches keeps its packages without branches, not 0 of 0")
        void noBranches() {
            CoverageReport report = read(CoverageFormat.JACOCO, "<report name=\"r\"><package name=\"\">"
                    + "<counter type=\"LINE\" missed=\"1\" covered=\"3\"/></package>"
                    + "<counter type=\"LINE\" missed=\"1\" covered=\"3\"/></report>");

            assertThat(report.packages().packages()).containsExactly(new Package("", new Counts(3, 4), Optional.empty()));
        }
    }

    @Nested
    @DisplayName("Cobertura")
    class Cobertura {

        @Test
        @DisplayName("counts each class's lines and condition coverage per package, never the lines repeated under a method")
        void packages() {
            CoverageReport report = sample(CoverageFormat.COBERTURA, "cobertura-packages.xml");

            assertThat(report.packages().packages()).containsExactly(
                    new Package("org/example/orders/service", new Counts(3, 4), Optional.of(new Counts(1, 4))),
                    new Package("org/example/orders/web", new Counts(1, 2), Optional.of(new Counts(2, 2))));
            addsUp(report);
        }

        @Test
        @DisplayName("a report whose lines do not add up to its stated totals keeps its totals and no package")
        void inconsistent() {
            CoverageReport report = sample(CoverageFormat.COBERTURA, "cobertura.xml");

            assertThat(report.lines()).isEqualTo(new Counts(30, 40));
            assertThat(report.packages().state()).isEqualTo(State.INCONSISTENT);
            assertThat(report.packages().packages()).isEmpty();
        }

        @Test
        @DisplayName("a condition coverage that does not read keeps no package, and refuses nothing")
        void unreadableCondition() {
            CoverageReport report = read(CoverageFormat.COBERTURA, "<coverage lines-valid=\"1\" lines-covered=\"1\">"
                    + "<packages><package name=\"a\"><classes><class name=\"a.B\" filename=\"a/B.java\"><lines>"
                    + "<line number=\"1\" hits=\"1\" branch=\"true\" condition-coverage=\"half\"/>"
                    + "</lines></class></classes></package></packages></coverage>");

            assertThat(report.lines()).isEqualTo(new Counts(1, 1));
            assertThat(report.packages().state()).isEqualTo(State.INCONSISTENT);
        }

        @Test
        @DisplayName("coverage.py's top-level package \".\" is the empty path")
        void topLevel() {
            CoverageReport report = read(CoverageFormat.COBERTURA, "<coverage lines-valid=\"2\" lines-covered=\"1\">"
                    + "<packages><package name=\".\"><classes><class name=\"main.py\" filename=\"main.py\"><lines>"
                    + "<line number=\"1\" hits=\"1\"/><line number=\"2\" hits=\"0\"/>"
                    + "</lines></class></classes></package></packages></coverage>");

            assertThat(report.packages().packages()).containsExactly(new Package("", new Counts(1, 2), Optional.empty()));
        }
    }

    @Nested
    @DisplayName("lcov")
    class Lcov {

        @Test
        @DisplayName("counts each file in its directory, after merging the records naming it")
        void directories() {
            CoverageReport report = sample(CoverageFormat.LCOV, "lcov-directories.info");

            assertThat(report.packages().packages()).containsExactly(
                    new Package("src", new Counts(1, 1), Optional.of(new Counts(0, 0))),
                    new Package("src/app/orders/service", new Counts(3, 4), Optional.of(new Counts(2, 2))),
                    new Package("src/app/orders/web", new Counts(2, 2), Optional.of(new Counts(0, 0))));
            addsUp(report);
        }

        @Test
        @DisplayName("the concatenated tracefile of the totals' test adds up too")
        void concatenated() {
            addsUp(sample(CoverageFormat.LCOV, "lcov.info"));
        }

        @Test
        @DisplayName("an absolute or Windows path is a path like any other, without its leading slash")
        void paths() {
            CoverageReport report = read(CoverageFormat.LCOV, "SF:/builds/team/shop/src/a.ts\nDA:1,1\nend_of_record\n"
                    + "SF:C:\\work\\shop\\src\\b.ts\nDA:1,0\nend_of_record\n");

            assertThat(report.packages().packages()).extracting(Package::path)
                    .containsExactly("C:/work/shop/src", "builds/team/shop/src");
        }

        @Test
        @DisplayName("50,000 files in as many directories: the totals are kept, the packages are not, and the import says so")
        void tooMany() {
            StringBuilder tracefile = new StringBuilder();
            for (int i = 0; i < 50_000; i++) {
                tracefile.append("SF:src/module").append(i).append("/index.ts\nDA:1,").append(i % 2).append("\nend_of_record\n");
            }

            CoverageReport report = read(CoverageFormat.LCOV, tracefile.toString());

            assertThat(report.lines()).isEqualTo(new Counts(25_000, 50_000));
            assertThat(report.packages()).isEqualTo(new CoveragePackages(State.TOO_MANY, java.util.List.of()));
            assertThat(State.TOO_MANY.why()).contains("more than 10000 packages");
        }

        @Test
        @DisplayName("exactly the limit is kept")
        void atTheLimit() {
            StringBuilder tracefile = new StringBuilder();
            for (int i = 0; i < CoveragePackages.MAX_PACKAGES; i++) {
                tracefile.append("SF:src/m").append(i).append("/x.ts\nDA:1,1\nend_of_record\n");
            }

            CoverageReport report = read(CoverageFormat.LCOV, tracefile.toString());

            assertThat(report.packages().packages()).hasSize(CoveragePackages.MAX_PACKAGES);
            addsUp(report);
        }

        @Test
        @DisplayName("a directory longer than the column is never clipped: no package is kept")
        void longPath() {
            String directory = "d".repeat(CoveragePackages.MAX_PATH + 1);
            CoverageReport report = read(CoverageFormat.LCOV, "SF:" + directory + "/a.ts\nDA:1,1\nend_of_record\n"
                    + "SF:src/b.ts\nDA:1,1\nend_of_record\n");

            assertThat(report.lines()).isEqualTo(new Counts(2, 2));
            assertThat(report.packages().state()).isEqualTo(State.PATH_REFUSED);

            String atBound = "d".repeat(CoveragePackages.MAX_PATH);
            assertThat(read(CoverageFormat.LCOV, "SF:" + atBound + "/a.ts\nDA:1,1\nend_of_record\n").packages().state())
                    .isEqualTo(State.KEPT);
        }

        @Test
        @DisplayName("a control character in a directory keeps no package — PostgreSQL refuses a NUL in a varchar")
        void controlCharacter() {
            CoverageReport report = read(CoverageFormat.LCOV, "SF:src\u0000x/a.ts\nDA:1,1\nend_of_record\n");

            assertThat(report.packages().state()).isEqualTo(State.PATH_REFUSED);
        }
    }

    @Test
    @DisplayName("a path is its segments joined by slashes: dots for the dotted formats, backslashes, empty and . segments")
    void path() {
        assertThat(CoveragePackages.path("org.example.service", true)).isEqualTo("org/example/service");
        assertThat(CoveragePackages.path("org/example/service/", false)).isEqualTo("org/example/service");
        assertThat(CoveragePackages.path("./src//app", false)).isEqualTo("src/app");
        assertThat(CoveragePackages.path("v1.2/api", false)).isEqualTo("v1.2/api");
        assertThat(CoveragePackages.directoryOf("main.ts")).isEmpty();
        assertThat(CoveragePackages.directoryOf("src\\app\\x.ts")).isEqualTo("src/app");
    }
}
