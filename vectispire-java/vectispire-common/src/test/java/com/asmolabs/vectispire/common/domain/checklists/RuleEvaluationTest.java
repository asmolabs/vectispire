package com.asmolabs.vectispire.common.domain.checklists;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.Component;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.CoverageReport;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.Imported;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.IssueCount;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.Look;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.PluginRun;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.PluginRuns;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.PluginState;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.Scanned;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.ScopeFacts;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.Source;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.Suite;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.TestReport;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * The rules over facts, with no database (decision 0032 §6): each way a line has no data, and the
 * thresholds judged only on complete data.
 */
@DisplayName("a rule's evaluation")
class RuleEvaluationTest {

    private static final Instant NOW = Instant.parse("2026-09-29T12:00:00Z");
    private static final Instant FRESH = NOW.minus(Duration.ofDays(1));
    private static final Instant OLD = NOW.minus(Duration.ofDays(30));

    private static final ChecklistRule SECRETS = ChecklistRule.parse("""
            {"kind":"findings_threshold","maxAgeDays":7,"scopes":["builtin:secret"],
             "thresholds":{"critical":{"maxOpen":0},"high":{"maxOpen":0}}}""");

    @Nested
    @DisplayName("no data is never a pass")
    class NoData {

        @Test
        @DisplayName("a project without repositories has no data: every one of none is not all")
        void noRepository() {
            Measurement measured = RuleEvaluation.evaluate(SECRETS, facts(List.of()).build(), NOW);
            assertThat(measured.outcome()).isEqualTo(MeasurementOutcome.NO_DATA);
            assertThat(measured.reason()).contains(NoDataReason.NO_REPOSITORY);
        }

        @Test
        @DisplayName("a step recorded absent in every scan within the age has no data, not a clean backlog")
        void stepAbsent() {
            Measurement measured = RuleEvaluation.evaluate(SECRETS, facts(List.of(1L))
                    .scope("builtin:secret", 1L, new Scanned(Optional.of(look(OLD)), true, 2, 0)).build(), NOW);
            assertThat(measured.outcome()).isEqualTo(MeasurementOutcome.NO_DATA);
            assertThat(measured.reason()).contains(NoDataReason.STEP_ABSENT);
        }

        @Test
        @DisplayName("scans from before the record of examined types say nothing of whether the step ran")
        void unrecorded() {
            Measurement measured = RuleEvaluation.evaluate(SECRETS, facts(List.of(1L))
                    .scope("builtin:secret", 1L, new Scanned(Optional.empty(), false, 0, 3)).build(), NOW);
            assertThat(measured.reason()).contains(NoDataReason.EXAMINATION_UNRECORDED);
        }

        @Test
        @DisplayName("a step that last produced before the maximum age is stale, one that never did is never examined")
        void staleAndNever() {
            assertThat(RuleEvaluation.evaluate(SECRETS, facts(List.of(1L))
                    .scope("builtin:secret", 1L, new Scanned(Optional.of(look(OLD)), true, 0, 0)).build(), NOW).reason())
                    .contains(NoDataReason.STALE);
            assertThat(RuleEvaluation.evaluate(SECRETS, facts(List.of(1L)).build(), NOW).reason())
                    .contains(NoDataReason.NEVER_EXAMINED);
        }

        @Test
        @DisplayName("one repository without data makes the line no data, whatever the others say")
        void oneRepositoryIsEnough() {
            Measurement measured = RuleEvaluation.evaluate(SECRETS, facts(List.of(1L, 2L))
                    .scope("builtin:secret", 1L, new Scanned(Optional.of(look(FRESH)), true, 1, 0)).build(), NOW);
            assertThat(measured.outcome()).isEqualTo(MeasurementOutcome.NO_DATA);
            assertThat(measured.repositories()).extracting(Measurement.RepositoryEvidence::status)
                    .containsExactly("examined", "never_examined");
        }

        @Test
        @DisplayName("a plugin not applicable on every repository has no data; not applicable on one leaves it out")
        void notApplicableAnywhere() {
            ChecklistRule rule = ChecklistRule.parse("{\"kind\":\"findings_threshold\",\"maxAgeDays\":7,"
                    + "\"scopes\":[\"plugin:java-arch\"],\"thresholds\":{\"high\":{\"maxOpen\":0}}}");
            PluginRuns skipped = new PluginRuns(List.of(new PluginRun(look(FRESH), PluginState.NOT_APPLICABLE)), 1, false);
            Measurement nowhere = RuleEvaluation.evaluate(rule, facts(List.of(1L, 2L))
                    .scope("plugin:java-arch", 1L, skipped).scope("plugin:java-arch", 2L, skipped).build(), NOW);
            assertThat(nowhere.outcome()).isEqualTo(MeasurementOutcome.NO_DATA);
            assertThat(nowhere.reason()).contains(NoDataReason.NOT_APPLICABLE_ANYWHERE);

            PluginRuns produced = new PluginRuns(List.of(new PluginRun(look(FRESH), PluginState.PRODUCED)), 1, false);
            Measurement somewhere = RuleEvaluation.evaluate(rule, facts(List.of(1L, 2L))
                    .scope("plugin:java-arch", 1L, produced).scope("plugin:java-arch", 2L, skipped)
                    .count("plugin:java-arch", 2L, "high", "open", 5).build(), NOW);
            assertThat(somewhere.outcome()).as("the repository it skipped is out of the figures").isEqualTo(MeasurementOutcome.PASS);
        }

        @Test
        @DisplayName("a plugin absent once within the age and never produced has no data, and so does one no scan ran")
        void pluginAbsent() {
            ChecklistRule rule = ChecklistRule.parse("{\"kind\":\"findings_threshold\",\"maxAgeDays\":7,"
                    + "\"scopes\":[\"plugin:java-arch\"],\"thresholds\":{\"high\":{\"maxOpen\":0}}}");
            PluginRuns absent = new PluginRuns(List.of(new PluginRun(look(FRESH), PluginState.NOT_APPLICABLE),
                    new PluginRun(look(FRESH.minusSeconds(60)), PluginState.ABSENT)), 2, false);
            assertThat(RuleEvaluation.evaluate(rule, facts(List.of(1L)).scope("plugin:java-arch", 1L, absent).build(), NOW)
                    .reason()).contains(NoDataReason.STEP_ABSENT);
            assertThat(RuleEvaluation.evaluate(rule, facts(List.of(1L))
                    .scope("plugin:java-arch", 1L, new PluginRuns(List.of(), 3, true)).build(), NOW).reason())
                    .as("scans ran without it").contains(NoDataReason.STEP_ABSENT);
            assertThat(RuleEvaluation.evaluate(rule, facts(List.of(1L))
                    .scope("plugin:java-arch", 1L, new PluginRuns(List.of(), 0, true)).build(), NOW).reason())
                    .contains(NoDataReason.STALE);
        }

        @Test
        @DisplayName("an imported tool: the import is the look, one before the record is unrecorded")
        void imports() {
            ChecklistRule rule = ChecklistRule.parse("{\"kind\":\"findings_threshold\",\"maxAgeDays\":7,"
                    + "\"scopes\":[\"import:ledger-ci/eslint\"],\"thresholds\":{\"high\":{\"maxOpen\":0}}}");
            assertThat(RuleEvaluation.evaluate(rule, facts(List.of(1L)).scope("import:ledger-ci/eslint", 1L,
                    new Imported(Optional.of(new Look(Source.SARIF_IMPORT, 9, FRESH, Optional.of("ab"))), false)).build(), NOW)
                    .outcome()).isEqualTo(MeasurementOutcome.PASS);
            assertThat(RuleEvaluation.evaluate(rule, facts(List.of(1L)).scope("import:ledger-ci/eslint", 1L,
                    new Imported(Optional.empty(), true)).build(), NOW).reason())
                    .contains(NoDataReason.EXAMINATION_UNRECORDED);
        }
    }

    @Nested
    @DisplayName("the thresholds")
    class Thresholds {

        @Test
        @DisplayName("pass on a clean backlog that looked, fail past a maximum, as of the oldest evidence")
        void passAndFail() {
            Instant older = FRESH.minus(Duration.ofHours(5));
            Builder facts = facts(List.of(1L, 2L))
                    .scope("builtin:secret", 1L, new Scanned(Optional.of(look(FRESH)), true, 1, 0))
                    .scope("builtin:secret", 2L, new Scanned(Optional.of(look(older)), true, 1, 0));
            Measurement clean = RuleEvaluation.evaluate(SECRETS, facts.build(), NOW);
            assertThat(clean.outcome()).isEqualTo(MeasurementOutcome.PASS);
            assertThat(clean.asOf()).contains(older);

            Measurement leaking = RuleEvaluation.evaluate(SECRETS, facts.count("builtin:secret", 2L, "high", "open", 1).build(),
                    NOW);
            assertThat(leaking.outcome()).isEqualTo(MeasurementOutcome.FAIL);
            assertThat(leaking.figures()).anySatisfy(figure -> {
                assertThat(figure.scope()).isEqualTo("all");
                assertThat(figure.severity()).isEqualTo("high");
                assertThat(figure.open()).isEqualTo(1);
                assertThat(figure.met()).contains(false);
            });
        }

        @Test
        @DisplayName("a state this version does not know is open; only resolved is resolved")
        void anUnknownStateStaysOpen() {
            Measurement measured = RuleEvaluation.evaluate(SECRETS, facts(List.of(1L))
                    .scope("builtin:secret", 1L, new Scanned(Optional.of(look(FRESH)), true, 1, 0))
                    .count("builtin:secret", 1L, "critical", "resolved", 4)
                    .count("builtin:secret", 1L, "critical", "quarantined", 1).build(), NOW);
            assertThat(measured.outcome()).isEqualTo(MeasurementOutcome.FAIL);
        }

        @Test
        @DisplayName("the resolved ratio is resolved over resolved and open, compared exactly")
        void resolvedRatio() {
            ChecklistRule rule = ChecklistRule.parse("{\"kind\":\"findings_threshold\",\"maxAgeDays\":7,"
                    + "\"scopes\":[\"builtin:sast\"],\"thresholds\":{\"medium\":{\"minResolvedRatio\":0.6}}}");
            Builder facts = facts(List.of(1L)).scope("builtin:sast", 1L, new Scanned(Optional.of(look(FRESH)), true, 1, 0));
            assertThat(RuleEvaluation.evaluate(rule, facts.build(), NOW).outcome())
                    .as("nothing to resolve").isEqualTo(MeasurementOutcome.PASS);
            assertThat(RuleEvaluation.evaluate(rule, facts.count("builtin:sast", 1L, "medium", "resolved", 3)
                    .count("builtin:sast", 1L, "medium", "open", 2).build(), NOW).outcome()).isEqualTo(MeasurementOutcome.PASS);
            assertThat(RuleEvaluation.evaluate(rule, facts.count("builtin:sast", 1L, "medium", "open", 1).build(), NOW)
                    .outcome()).isEqualTo(MeasurementOutcome.FAIL);
        }

        @Test
        @DisplayName("a threshold is never judged on a partial backlog")
        void notOnPartialData() {
            Measurement measured = RuleEvaluation.evaluate(SECRETS, facts(List.of(1L, 2L))
                    .scope("builtin:secret", 1L, new Scanned(Optional.of(look(FRESH)), true, 1, 0))
                    .count("builtin:secret", 1L, "critical", "open", 9).build(), NOW);
            assertThat(measured.outcome()).isEqualTo(MeasurementOutcome.NO_DATA);
            assertThat(measured.figures()).filteredOn(figure -> figure.scope().equals("all"))
                    .allSatisfy(figure -> assertThat(figure.met()).isEmpty());
        }
    }

    @Nested
    @DisplayName("the other kinds")
    class Kinds {

        @Test
        @DisplayName("dependency analysis: the scan stored an SBOM, and the schedule matches when asked")
        void dependencies() {
            ChecklistRule rule = ChecklistRule.parse("{\"kind\":\"dependency_analysis\",\"maxAgeDays\":7,\"requireSchedule\":true}");
            Builder facts = facts(List.of(1L))
                    .scope("builtin:vulnerability", 1L, new Scanned(Optional.of(look(FRESH)), true, 1, 0));
            assertThat(RuleEvaluation.evaluate(rule, facts.build(), NOW).outcome()).as("not scheduled")
                    .isEqualTo(MeasurementOutcome.FAIL);
            assertThat(RuleEvaluation.evaluate(rule, facts.scheduled(1L, true).build(), NOW).outcome())
                    .isEqualTo(MeasurementOutcome.PASS);
            assertThat(RuleEvaluation.evaluate(rule, facts.scope("builtin:vulnerability", 1L,
                    new Scanned(Optional.of(look(FRESH)), false, 1, 0)).build(), NOW).outcome())
                    .as("no SBOM stored").isEqualTo(MeasurementOutcome.FAIL);
        }

        @Test
        @DisplayName("coverage: per repository or weighted, and a report that counted no branch is no data")
        void coverage() {
            ChecklistRule lines = ChecklistRule.parse("{\"kind\":\"coverage_threshold\",\"maxAgeDays\":7,\"metric\":\"line\","
                    + "\"minimumRatio\":0.8,\"aggregation\":\"per_repository\"}");
            ChecklistRule weighted = ChecklistRule.parse("{\"kind\":\"coverage_threshold\",\"maxAgeDays\":7,"
                    + "\"metric\":\"line\",\"minimumRatio\":0.8,\"aggregation\":\"project_weighted\"}");
            ChecklistRule branches = ChecklistRule.parse("{\"kind\":\"coverage_threshold\",\"maxAgeDays\":7,"
                    + "\"metric\":\"branch\",\"minimumRatio\":0.5,\"aggregation\":\"per_repository\"}");
            Builder facts = facts(List.of(1L, 2L))
                    .coverage(1L, new CoverageReport(new Look(Source.COVERAGE_IMPORT, 1, FRESH, Optional.of("aa")), 900, 1000,
                            Optional.empty(), Optional.empty()))
                    .coverage(2L, new CoverageReport(new Look(Source.COVERAGE_IMPORT, 2, FRESH, Optional.of("bb")), 70, 100,
                            Optional.of(1L), Optional.of(2L)));
            assertThat(RuleEvaluation.evaluate(lines, facts.build(), NOW).outcome()).isEqualTo(MeasurementOutcome.FAIL);
            assertThat(RuleEvaluation.evaluate(weighted, facts.build(), NOW).outcome())
                    .as("970 of 1100").isEqualTo(MeasurementOutcome.PASS);
            Measurement noBranch = RuleEvaluation.evaluate(branches, facts.build(), NOW);
            assertThat(noBranch.reason()).contains(NoDataReason.STEP_ABSENT);
            assertThat(RuleEvaluation.evaluate(lines, facts(List.of(1L)).coverage(1L, new CoverageReport(
                    new Look(Source.COVERAGE_IMPORT, 1, OLD, Optional.empty()), 1, 1, Optional.empty(), Optional.empty()))
                    .build(), NOW).reason()).contains(NoDataReason.STALE);
        }

        @Test
        @DisplayName("tests: a suite must match, run tests not skipped, and none fail")
        void tests() {
            ChecklistRule rule = ChecklistRule.parse("{\"kind\":\"test_suite_passed\",\"maxAgeDays\":7,"
                    + "\"suitePattern\":\"com.example.arch.*\",\"minimumTests\":3}");
            Look at = new Look(Source.TEST_REPORT_IMPORT, 5, FRESH, Optional.of("cc"));
            assertThat(RuleEvaluation.evaluate(rule, facts(List.of(1L)).tests(1L, new TestReport(at,
                    List.of(new Suite("com.example.AppTest", 9, 0, 0, 0)))).build(), NOW).reason())
                    .contains(NoDataReason.SUITE_NOT_FOUND);
            assertThat(RuleEvaluation.evaluate(rule, facts(List.of(1L)).tests(1L, new TestReport(at,
                    List.of(new Suite("com.example.arch.LayersTest", 4, 0, 0, 4)))).build(), NOW).reason())
                    .contains(NoDataReason.NO_TEST_RAN);
            assertThat(RuleEvaluation.evaluate(rule, facts(List.of(1L)).tests(1L, new TestReport(at,
                    List.of(new Suite("com.example.arch.LayersTest", 4, 1, 0, 0)))).build(), NOW).outcome())
                    .isEqualTo(MeasurementOutcome.FAIL);
            assertThat(RuleEvaluation.evaluate(rule, facts(List.of(1L)).tests(1L, new TestReport(at,
                    List.of(new Suite("com.example.arch.LayersTest", 4, 0, 0, 2)))).build(), NOW).outcome())
                    .as("two ran, three asked").isEqualTo(MeasurementOutcome.FAIL);
            assertThat(RuleEvaluation.evaluate(rule, facts(List.of(1L)).tests(1L, new TestReport(at,
                    List.of(new Suite("com.example.arch.LayersTest", 4, 0, 0, 0)))).build(), NOW).outcome())
                    .isEqualTo(MeasurementOutcome.PASS);
        }

        @Test
        @DisplayName("components: every declared package present at an allowed version, every occurrence")
        void components() {
            ChecklistRule rule = ChecklistRule.parse("{\"kind\":\"component_versions\",\"maxAgeDays\":7,\"components\":["
                    + "{\"purlPrefix\":\"pkg:maven/com.example/ledger-core\",\"versions\":[\"3.2.1\"]}]}");
            Builder facts = facts(List.of(1L))
                    .scope("builtin:vulnerability", 1L, new Scanned(Optional.of(look(FRESH)), true, 1, 0));
            assertThat(RuleEvaluation.evaluate(rule, facts.components(1L, List.of(
                    new Component("ledger-core", "3.2.1", "pkg:maven/com.example/ledger-core@3.2.1"))).build(), NOW).outcome())
                    .isEqualTo(MeasurementOutcome.PASS);
            assertThat(RuleEvaluation.evaluate(rule, facts.components(1L, List.of(
                    new Component("ledger-core", "3.2.1", "pkg:maven/com.example/ledger-core@3.2.1"),
                    new Component("ledger-core", "2.0.0", "pkg:maven/com.example/ledger-core@2.0.0"))).build(), NOW)
                    .outcome()).as("one occurrence at another version").isEqualTo(MeasurementOutcome.FAIL);
            assertThat(RuleEvaluation.evaluate(rule, facts.components(1L, List.of()).build(), NOW).outcome())
                    .as("not present").isEqualTo(MeasurementOutcome.FAIL);
        }
    }

    @Test
    @DisplayName("the stored evidence reads back as written, and its digest follows it")
    void evidenceRoundTrip() {
        Measurement measured = RuleEvaluation.evaluate(SECRETS, facts(List.of(1L, 2L))
                .scope("builtin:secret", 1L, new Scanned(Optional.of(look(FRESH)), true, 1, 0))
                .count("builtin:secret", 1L, "high", "open", 2).build(), NOW);
        Measurement read = Measurement.read(measured.evidenceJson());
        assertThat(read).isEqualTo(measured);
        assertThat(read.evidenceDigest()).isEqualTo(measured.evidenceDigest());
    }

    private static Look look(Instant at) {
        return new Look(Source.SCAN, at.getEpochSecond(), at, Optional.empty());
    }

    private static Builder facts(List<Long> repositories) {
        return new Builder(repositories);
    }

    /** Facts built a question at a time; a map left empty is an owner that knows nothing. */
    private static final class Builder {
        private final List<Long> repositories;
        private final Map<String, Map<Long, ScopeFacts>> scopes = new HashMap<>();
        private final Map<String, Map<Long, List<IssueCount>>> counts = new HashMap<>();
        private final Map<Long, Boolean> scheduled = new HashMap<>();
        private final Map<Long, CoverageReport> coverage = new HashMap<>();
        private final Map<Long, TestReport> tests = new HashMap<>();
        private final Map<Long, List<Component>> components = new HashMap<>();

        Builder(List<Long> repositories) {
            this.repositories = repositories;
        }

        Builder scope(String key, long repository, ScopeFacts facts) {
            scopes.computeIfAbsent(key, ignored -> new HashMap<>()).put(repository, facts);
            return this;
        }

        Builder count(String key, long repository, String severity, String state, long count) {
            counts.computeIfAbsent(key, ignored -> new HashMap<>())
                    .computeIfAbsent(repository, ignored -> new java.util.ArrayList<>())
                    .add(new IssueCount(severity, state, count));
            return this;
        }

        Builder scheduled(long repository, boolean met) {
            scheduled.put(repository, met);
            return this;
        }

        Builder coverage(long repository, CoverageReport report) {
            coverage.put(repository, report);
            return this;
        }

        Builder tests(long repository, TestReport report) {
            tests.put(repository, report);
            return this;
        }

        Builder components(long repository, List<Component> listed) {
            components.put(repository, listed);
            return this;
        }

        MeasurementFacts build() {
            Map<String, Map<Long, List<IssueCount>>> copied = new HashMap<>();
            counts.forEach((key, byRepository) -> {
                Map<Long, List<IssueCount>> inner = new HashMap<>();
                byRepository.forEach((repository, list) -> inner.put(repository, List.copyOf(list)));
                copied.put(key, inner);
            });
            return new MeasurementFacts(repositories, scopes, copied, scheduled, coverage, tests, components);
        }
    }
}
