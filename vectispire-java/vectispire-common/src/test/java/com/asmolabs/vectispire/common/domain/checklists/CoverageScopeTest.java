package com.asmolabs.vectispire.common.domain.checklists;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.CoverageReport;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.Kept;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.Look;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.NotKept;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.PackageCounts;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.Source;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.Unrecorded;
import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * The scope of a {@code coverage_threshold} rule: its patterns, refused in words when they would not
 * read as written; how it is bound and written; and what a scoped measurement says — the figure over
 * the packages it matches, or no data with the reason, never 0 % nor 100 % nor the report's totals in
 * its place.
 */
@DisplayName("a coverage rule's scope")
class CoverageScopeTest {

    private static final Instant NOW = Instant.parse("2026-10-03T12:00:00Z");
    private static final Instant FRESH = NOW.minus(Duration.ofDays(1));
    private static final String UNSCOPED = "{\"kind\":\"coverage_threshold\",\"maxAgeDays\":7,\"metric\":\"line\","
            + "\"minimumRatio\":0.8,\"aggregation\":\"per_repository\"}";

    private static ChecklistRule scoped(String metric, String scope) {
        return ChecklistRule.parse("{\"kind\":\"coverage_threshold\",\"maxAgeDays\":7,\"metric\":\"" + metric + "\","
                + "\"minimumRatio\":0.8,\"aggregation\":\"per_repository\",\"scope\":" + scope + "}");
    }

    private static PackageCounts part(String path, long covered, long total) {
        return new PackageCounts(path, covered, total, Optional.of(covered / 2), Optional.of(total / 2));
    }

    /**
     * An invented report: the service layer well covered, the generated code not at all, the web layer
     * half — 46 of 100 lines over the whole report.
     */
    private static final List<PackageCounts> ORDERS = List.of(
            part("org/example/orders/generated", 0, 40),
            part("org/example/orders/service", 36, 40),
            part("org/example/orders/service/impl", 4, 4),
            part("org/example/orders/web", 6, 16));

    private static Measurement measure(ChecklistRule rule, MeasurementFacts.Packages packages) {
        CoverageReport report = new CoverageReport(new Look(Source.COVERAGE_IMPORT, 9, FRESH, Optional.of("ab")), 46, 100,
                Optional.of(23L), Optional.of(50L), packages);
        return RuleEvaluation.evaluate(rule, new MeasurementFacts(List.of(1L), Map.of(), Map.of(), Map.of(),
                Map.of(1L, report), Map.of(), Map.of()), NOW);
    }

    @Nested
    @DisplayName("matching paths")
    class Matching {

        private boolean in(String pattern, String path) {
            return new CoverageScope(List.of(pattern), List.of()).matches(path);
        }

        @Test
        @DisplayName("** is any number of segments, none included")
        void doubleStar() {
            assertThat(in("**/service/**", "org/example/orders/service")).isTrue();
            assertThat(in("**/service/**", "org/example/orders/service/impl")).isTrue();
            assertThat(in("**/service/**", "service")).isTrue();
            assertThat(in("**/service/**", "org/example/orders/services")).isFalse();
            assertThat(in("**/service/**", "org/example/orders/web")).isFalse();
            assertThat(in("**", "")).as("the top level").isTrue();
            assertThat(in("org/**/impl", "org/impl")).isTrue();
            assertThat(in("org/**/impl", "org/a/b/impl")).isTrue();
            assertThat(in("org/**/impl", "org/a/b/impl/x")).isFalse();
        }

        @Test
        @DisplayName("* is characters within one segment, never a slash")
        void star() {
            assertThat(in("org/example/*-api", "org/example/orders-api")).isTrue();
            assertThat(in("org/example/*-api", "org/example/orders/x-api")).isFalse();
            assertThat(in("org/*/service", "org/example/service")).isTrue();
            assertThat(in("org/*/service", "org/service")).isFalse();
            assertThat(in("src/*", "src/a.b")).isTrue();
            assertThat(in("a*b*c", "aXbYc")).isTrue();
            assertThat(in("a*b*c", "aXbY")).isFalse();
        }

        @Test
        @DisplayName("a pattern without a wildcard is that package alone, not its subpackages; case counts")
        void literal() {
            assertThat(in("org/example", "org/example")).isTrue();
            assertThat(in("org/example", "org/example/service")).isFalse();
            assertThat(in("org/example/**", "org/example")).isTrue();
            assertThat(in("org/example", "Org/Example")).isFalse();
        }

        @Test
        @DisplayName("in when an include matches — every package when none is given — and no exclude does")
        void includeAndExclude() {
            CoverageScope both = new CoverageScope(List.of("org/example/**"), List.of("**/generated/**"));
            assertThat(both.matches("org/example/orders/service")).isTrue();
            assertThat(both.matches("org/example/orders/generated")).isFalse();
            assertThat(both.matches("com/other")).isFalse();
            CoverageScope excludeOnly = new CoverageScope(null, List.of("**/generated/**"));
            assertThat(excludeOnly.matches("com/other")).isTrue();
            assertThat(excludeOnly.matches("com/other/generated/x")).isFalse();
        }

        @Test
        @DisplayName("a pathological pattern over a long path ends at once")
        void linear() {
            String pattern = String.join("/", java.util.Collections.nCopies(60, "**")) + "/z";
            String path = String.join("/", java.util.Collections.nCopies(400, "a"));
            long start = System.nanoTime();
            assertThat(new CoverageScope(List.of(pattern), List.of()).matches(path)).isFalse();
            assertThat(Duration.ofNanos(System.nanoTime() - start)).isLessThan(Duration.ofSeconds(2));
            assertThat(CoverageScope.segment("*a*a*a*a*a*a*a*b", "a".repeat(200))).isFalse();
        }
    }

    @Nested
    @DisplayName("binding it")
    class Binding {

        private void refused(String scope, String words) {
            assertThatThrownBy(() -> scoped("line", scope))
                    .isInstanceOf(InvalidInputException.class)
                    .hasMessageContaining(words);
        }

        @Test
        @DisplayName("a pattern that would not read as its writer meant is refused in words")
        void refusals() {
            refused("{\"include\":[\"org.example.service\"]}", "write org/example/service");
            refused("{\"include\":[\"**/serv**\"]}", "** inside a segment");
            refused("{\"include\":[\"org/?/x\"]}", "only * (within a segment) and ** (any number of segments)");
            refused("{\"include\":[\"src/{a,b}\"]}", "only *");
            refused("{\"include\":[\"/org/example\"]}", "no leading or trailing slash");
            refused("{\"include\":[\"org/example/\"]}", "no leading or trailing slash");
            refused("{\"include\":[\"org//example\"]}", "empty segment");
            refused("{\"include\":[\"org\\\\example\"]}", "backslash");
            refused("{\"include\":[\"org/../x\"]}", "\"..\" segment");
            refused("{\"include\":[\"  \"]}", "is empty");
            refused("{\"include\":[\"" + "a/".repeat(300) + "a\"]}", "1 to 500 characters");
            refused("{\"include\":[\"a/b\",\"a/b\"]}", "twice");
            refused("{}", "at least one pattern");
            refused("{\"include\":[],\"exclude\":[]}", "at least one pattern");
            refused("{\"only\":[\"a/b\"]}", "takes include and exclude");
            refused("\"**/service/**\"", "scope is an object");
            refused("{\"include\":\"a/b\"}", "is a list of patterns");
            refused("{\"include\":[3]}", "is a string");
            String many = String.join(",", java.util.stream.IntStream.range(0, 21).mapToObj(i -> "\"p" + i + "/x\"").toList());
            refused("{\"exclude\":[" + many + "]}", "at most 20 patterns");
        }

        @Test
        @DisplayName("another kind takes no scope")
        void otherKinds() {
            assertThatThrownBy(() -> ChecklistRule.parse("{\"kind\":\"test_suite_passed\",\"maxAgeDays\":7,"
                            + "\"suitePattern\":\"*\",\"minimumTests\":1,\"scope\":{\"include\":[\"a/b\"]}}"))
                    .hasMessageContaining("takes no \"scope\"");
        }

        @Test
        @DisplayName("no scope is today's rule, byte for byte: the canonical form and its digest do not move")
        void noScopeUnchanged() {
            ChecklistRule rule = ChecklistRule.parse(UNSCOPED);

            assertThat(rule.canonical()).isEqualTo("{\"aggregation\":\"per_repository\",\"kind\":\"coverage_threshold\","
                    + "\"maxAgeDays\":7,\"metric\":\"line\",\"minimumRatio\":0.8}");
            assertThat(((ChecklistRule.CoverageThreshold) rule).scope()).isEmpty();
            assertThat(ChecklistRule.parse(UNSCOPED.replace("}", ",\"scope\":null}")).canonical())
                    .isEqualTo(rule.canonical());
        }

        @Test
        @DisplayName("a scope is written sorted, an empty list left out, and read back the same")
        void canonical() {
            ChecklistRule rule = scoped("line", "{\"include\":[\"org/example/**\",\"**/service/**\"]}");

            assertThat(rule.canonical()).isEqualTo("{\"aggregation\":\"per_repository\",\"kind\":\"coverage_threshold\","
                    + "\"maxAgeDays\":7,\"metric\":\"line\",\"minimumRatio\":0.8,"
                    + "\"scope\":{\"include\":[\"**/service/**\",\"org/example/**\"]}}");
            assertThat(ChecklistRule.fromCanonical(rule.canonical())).isEqualTo(rule);
            assertThat(scoped("line", "{\"include\":[\"**/service/**\",\"org/example/**\"],\"exclude\":[]}").digest())
                    .isEqualTo(rule.digest());
            assertThat(scoped("line", "{\"include\":[\"org/example/**\"],\"exclude\":[\"**/generated/**\"]}").canonical())
                    .endsWith("\"scope\":{\"exclude\":[\"**/generated/**\"],\"include\":[\"org/example/**\"]}}");
            assertThat(scoped("line", "{\"exclude\":[\"**/generated/**\"]}").canonical())
                    .as("an empty include is left out, not written as []")
                    .endsWith("\"scope\":{\"exclude\":[\"**/generated/**\"]}}");
        }
    }

    @Nested
    @DisplayName("measuring over it")
    class Measuring {

        @Test
        @DisplayName("include: the figure over the matching packages alone, the count of packages in the evidence")
        void include() {
            Measurement measured = measure(scoped("line", "{\"include\":[\"**/service/**\"]}"), new Kept(ORDERS));

            assertThat(measured.outcome()).as("40 of 44").isEqualTo(MeasurementOutcome.PASS);
            assertThat(measured.repositories().getFirst().detail())
                    .contains("2 of 4 packages in the scope; 40 of 44 lines covered");
            assertThat(measured.summary()).contains("line coverage of at least 80 % over packages matching **/service/**")
                    .as("a pass names its figure beside its scope")
                    .endsWith(": repository 1: 2 of 4 packages in the scope; 40 of 44 lines covered.");
        }

        @Test
        @DisplayName("exclude: everything but the matching packages")
        void exclude() {
            Measurement measured = measure(scoped("line", "{\"exclude\":[\"**/generated/**\",\"**/web\"]}"), new Kept(ORDERS));

            assertThat(measured.outcome()).isEqualTo(MeasurementOutcome.PASS);
            assertThat(measured.repositories().getFirst().detail()).contains("2 of 4 packages in the scope; 40 of 44 lines covered");
            assertThat(measured.summary()).contains("over every package, excluding **/generated/**, **/web");
        }

        @Test
        @DisplayName("both: what an include matches less what an exclude does — and the failure names the scope")
        void both() {
            Measurement measured = measure(scoped("line", "{\"include\":[\"org/example/orders/**\"],"
                    + "\"exclude\":[\"**/service/**\"]}"), new Kept(ORDERS));

            assertThat(measured.outcome()).as("6 of 56").isEqualTo(MeasurementOutcome.FAIL);
            assertThat(measured.summary()).contains("over packages matching org/example/orders/**, excluding **/service/**")
                    .contains("2 of 4 packages in the scope; 6 of 56 lines covered, under 80 %");
        }

        @Test
        @DisplayName("branches over the scope are the matching packages' branches")
        void branches() {
            Measurement measured = measure(scoped("branch", "{\"include\":[\"**/service\"]}"), new Kept(ORDERS));

            assertThat(measured.repositories().getFirst().detail()).contains("1 of 4 packages in the scope; 18 of 20 branchs covered");
        }

        @Test
        @DisplayName("a scope matching nothing is no data — never 0 %, never 100 %")
        void nothingMatches() {
            Measurement measured = measure(scoped("line", "{\"include\":[\"com/other/**\"]}"), new Kept(ORDERS));

            assertThat(measured.outcome()).isEqualTo(MeasurementOutcome.NO_DATA);
            assertThat(measured.reason()).contains(NoDataReason.SCOPE_MATCHES_NOTHING);
            assertThat(measured.summary()).contains("none of the report's 4 packages is in packages matching com/other/**");
        }

        @Test
        @DisplayName("an import from before packages were kept is no data, re-import needed — never its totals")
        void oldImport() {
            Measurement measured = measure(scoped("line", "{\"include\":[\"**/service/**\"]}"), new Unrecorded());

            assertThat(measured.outcome()).isEqualTo(MeasurementOutcome.NO_DATA);
            assertThat(measured.reason()).contains(NoDataReason.PACKAGES_UNRECORDED);
            assertThat(measured.summary()).contains("re-import the report");
        }

        @Test
        @DisplayName("an import that did not keep its packages is no data, and says why")
        void notKept() {
            Measurement measured = measure(scoped("line", "{\"include\":[\"**/service/**\"]}"),
                    new NotKept("the report names more than 10000 packages"));

            assertThat(measured.reason()).contains(NoDataReason.PACKAGES_NOT_KEPT);
            assertThat(measured.summary()).contains("more than 10000 packages");
        }

        @Test
        @DisplayName("scoped packages that count no branch are no data for a branch rule")
        void noBranchInScope() {
            Measurement measured = measure(scoped("branch", "{\"include\":[\"**/generated\"]}"), new Kept(List.of(
                    new PackageCounts("org/example/generated", 0, 10, Optional.of(0L), Optional.of(0L)),
                    new PackageCounts("org/example/service", 5, 10, Optional.of(23L), Optional.of(50L)))));

            assertThat(measured.reason()).contains(NoDataReason.STEP_ABSENT);
        }

        @Test
        @DisplayName("no scope reads the totals and never the packages, exactly as before")
        void unscoped() {
            Measurement measured = measure(ChecklistRule.parse(UNSCOPED), new Unrecorded());

            assertThat(measured.outcome()).as("46 of 100").isEqualTo(MeasurementOutcome.FAIL);
            assertThat(measured.summary()).isEqualTo("Fail, line coverage of at least 80 %: repository 1: 46 of 100 lines "
                    + "covered, under 80 %.");
        }
    }
}
