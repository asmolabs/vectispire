package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.access.VisibilityMode;
import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.access.persistence.UserRepository;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogEntity;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogRepository;
import com.asmolabs.vectispire.core.checklists.ChecklistMeasurementsView;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistAnswerRepository;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistMeasurementRepository;
import com.asmolabs.vectispire.core.inventory.persistence.ComponentEntity;
import com.asmolabs.vectispire.core.inventory.persistence.ComponentRepository;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import com.asmolabs.vectispire.core.plugins.persistence.CoverageImportEntity;
import com.asmolabs.vectispire.core.plugins.persistence.CoverageImportRepository;
import com.asmolabs.vectispire.core.plugins.persistence.SarifImportEntity;
import com.asmolabs.vectispire.core.plugins.persistence.SarifImportRepository;
import com.asmolabs.vectispire.core.plugins.persistence.TestReportImportEntity;
import com.asmolabs.vectispire.core.plugins.persistence.TestReportImportRepository;
import com.asmolabs.vectispire.core.plugins.persistence.TestSuiteResultEntity;
import com.asmolabs.vectispire.core.plugins.persistence.TestSuiteResultRepository;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.targets.TargetNaming;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;

/**
 * A checklist line's measurements through the real routes, over rows the owners wrote (decision 0032
 * §6): each way a line has no data and says why, the backlog's figures with settled triage out and an
 * unknown status in, the imports and SBOM components the other kinds read, and the three places a
 * measurement is relied on — an answer resting on one, the submission's reconciliation, and the
 * sign-off's re-judged freshness.
 *
 * <p>The evidence is written straight into the owners' tables, as a scan or an import leaves it:
 * what is under test is the reading of it, and a scanner would add nothing but minutes.
 */
@DisplayName("checklist measurements, through the routes")
class ChecklistMeasurementsRoutesTest extends ApiTestBase {

    private static final String TEMPLATES = "/api/v1/checklist-templates";
    private static final String PROBLEM = "urn:vectispire:problem:";

    private static final Map<String, Object> SECRETS = Map.of("kind", "findings_threshold", "maxAgeDays", 7,
            "scopes", List.of("builtin:secret"), "thresholds", Map.of("critical", Map.of("maxOpen", 0),
                    "high", Map.of("maxOpen", 0)));

    @Autowired
    private SettingsService settings;

    @Autowired
    private AuditLogRepository auditLog;

    @Autowired
    private UserRepository users;

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private ScanRepository scans;

    @Autowired
    private IssueRepository issues;

    @Autowired
    private ComponentRepository components;

    @Autowired
    private SarifImportRepository sarifImports;

    @Autowired
    private CoverageImportRepository coverageImports;

    @Autowired
    private TestReportImportRepository testReports;

    @Autowired
    private TestSuiteResultRepository suites;

    @Autowired
    private ChecklistAnswerRepository answers;

    @Autowired
    private ChecklistMeasurementRepository measurements;

    private record Account(String token, long id, String name) {}

    private Account developer;
    private Account ciso;
    private long project;
    private long first;
    private long second;

    @BeforeEach
    void estate() throws Exception {
        settings.set(Setting.FOUR_EYES_APPROVAL_REQUIRED, "false");
        developer = account(Role.USER);
        ciso = account(Role.CISO);
        project = project("Checkout");
        first = repository("https://example.invalid/checkout-api.git", 1_440);
        second = repository("https://example.invalid/checkout-web.git", 1_440);
        file(project, first);
        file(project, second);
    }

    // ------------------------------------------------------------------ no data is never a pass

    @Nested
    @DisplayName("no data is never a pass")
    class NoData {

        @Test
        @DisplayName("a project without repositories has no data: every one of none is not all")
        void aProjectWithoutRepositories() throws Exception {
            publishWithRule(SECRETS);
            long empty = project("Later");
            grantAll();
            open(developer, empty);
            JsonNode line = measurements(developer, empty, 1).at("/lines/0");
            assertThat(line.at("/measurement/outcome").asText()).isEqualTo("no_data");
            assertThat(line.at("/measurement/reason").asText()).isEqualTo("no_repository");
            assertThat(line.at("/measurement/id").isNull()).as("computed for the read, stored nowhere").isTrue();
            assertThat(measurements.findAll()).isEmpty();
        }

        @Test
        @DisplayName("a step absent in every scan within the age has no data, whatever the backlog says")
        void anAbsentStep() throws Exception {
            publishWithRule(SECRETS);
            scan(first, hoursAgo(2), "sast,iac", null, true);
            scan(second, hoursAgo(2), "secret", null, true);
            open(developer, project);
            JsonNode measurement = measurements(developer, project, 1).at("/lines/0/measurement");
            assertThat(measurement.at("/outcome").asText()).isEqualTo("no_data");
            assertThat(measurement.at("/reason").asText()).isEqualTo("step_absent");
            assertThat(statusOf(measurement, first)).isEqualTo("step_absent");
            assertThat(statusOf(measurement, second)).isEqualTo("examined");
        }

        @Test
        @DisplayName("a scan from before examined_types says nothing of whether the step ran")
        void anUnrecordedScan() throws Exception {
            publishWithRule(SECRETS);
            scan(first, hoursAgo(2), null, null, true);
            scan(second, hoursAgo(2), "secret", null, true);
            open(developer, project);
            assertThat(measurements(developer, project, 1).at("/lines/0/measurement/reason").asText())
                    .isEqualTo("examination_unrecorded");
        }

        @Test
        @DisplayName("a scan older than the maximum age is stale")
        void aStaleScan() throws Exception {
            publishWithRule(SECRETS);
            scan(first, Instant.now().minus(Duration.ofDays(30)), "secret", null, true);
            scan(second, hoursAgo(2), "secret", null, true);
            open(developer, project);
            JsonNode measurement = measurements(developer, project, 1).at("/lines/0/measurement");
            assertThat(measurement.at("/reason").asText()).isEqualTo("stale");
            assertThat(statusOf(measurement, first)).isEqualTo("stale");
        }

        @Test
        @DisplayName("a plugin not applicable on every repository has no data; produced on one, the other is left out")
        void aPluginNotApplicableAnywhere() throws Exception {
            publishWithRule(Map.of("kind", "findings_threshold", "maxAgeDays", 7, "scopes", List.of("plugin:java-arch"),
                    "thresholds", Map.of("high", Map.of("maxOpen", 0))));
            scan(first, hoursAgo(2), "secret", plugin("java-arch", "not_applicable"), true);
            scan(second, hoursAgo(2), "secret", plugin("java-arch", "not_applicable"), true);
            issue(first, "plugin", "plugin:java-arch", "high", "open", "under_review");
            open(developer, project);
            assertThat(measurements(developer, project, 1).at("/lines/0/measurement/reason").asText())
                    .isEqualTo("not_applicable_anywhere");

            scan(second, hoursAgo(1), "secret", plugin("java-arch", "produced"), true);
            JsonNode somewhere = measurements(developer, project, 1).at("/lines/0/measurement");
            assertThat(somewhere.at("/outcome").asText())
                    .as("the repository it skipped is out of the figures, its old issue with it").isEqualTo("pass");
            assertThat(statusOf(somewhere, first)).isEqualTo("not_applicable");
        }

        @Test
        @DisplayName("an imported tool: the import carrying it is the look, one from before the record is unrecorded")
        void anImportedTool() throws Exception {
            publishWithRule(Map.of("kind", "findings_threshold", "maxAgeDays", 7,
                    "scopes", List.of("import:ledger-ci/eslint"), "thresholds", Map.of("high", Map.of("maxOpen", 0))));
            sarifImport(first, "import:ledger-ci/eslint", hoursAgo(1));
            sarifImport(second, null, hoursAgo(1));
            open(developer, project);
            assertThat(measurements(developer, project, 1).at("/lines/0/measurement/reason").asText())
                    .isEqualTo("examination_unrecorded");

            long carrying = sarifImport(second, "import:ledger-ci/eslint,import:ledger-ci/semgrep", hoursAgo(0));
            JsonNode measurement = measurements(developer, project, 1).at("/lines/0/measurement");
            assertThat(measurement.at("/outcome").asText()).isEqualTo("pass");
            JsonNode look = repository(measurement, second);
            assertThat(look.at("/source").asText()).isEqualTo("sarif_import");
            assertThat(look.at("/sourceId").asLong()).isEqualTo(carrying);
            assertThat(look.at("/digest").asText()).as("the document the import accepted").hasSize(64);
        }
    }

    // ------------------------------------------------------------------ the backlog's figures

    @Nested
    @DisplayName("the backlog's figures")
    class Figures {

        @Test
        @DisplayName("a settled finding leaves the counts, and the same finding unsettled fails the line")
        void aSettledFindingLeavesTheCounts() throws Exception {
            publishWithRule(SECRETS);
            scan(first, hoursAgo(2), "secret", null, true);
            scan(second, hoursAgo(2), "secret", null, true);
            long leaked = issue(first, "secret", null, "critical", "open", "not_affected");
            open(developer, project);
            JsonNode settled = measurements(developer, project, 1).at("/lines/0/measurement");
            assertThat(settled.at("/outcome").asText()).isEqualTo("pass");

            IssueEntity row = issues.findById(leaked).orElseThrow();
            row.setTriageStatus("affected");
            issues.save(row);
            JsonNode open = measurements(developer, project, 1).at("/lines/0/measurement");
            assertThat(open.at("/outcome").asText()).isEqualTo("fail");
            assertThat(total(open, "critical").at("/open").asLong()).isEqualTo(1);
            assertThat(total(open, "critical").at("/met").asBoolean()).isFalse();
        }

        @Test
        @DisplayName("a triage status this version does not know stays open")
        void anUnknownStatusStaysOpen() throws Exception {
            publishWithRule(SECRETS);
            scan(first, hoursAgo(2), "secret", null, true);
            scan(second, hoursAgo(2), "secret", null, true);
            issue(second, "secret", null, "high", "open", "escalated_to_vendor");
            open(developer, project);
            JsonNode measurement = measurements(developer, project, 1).at("/lines/0/measurement");
            assertThat(measurement.at("/outcome").asText()).isEqualTo("fail");
            assertThat(total(measurement, "high").at("/open").asLong()).isEqualTo(1);
        }

        @Test
        @DisplayName("a resolved ratio counts resolved over resolved and open, per severity, over every scope named")
        void aResolvedRatio() throws Exception {
            publishWithRule(Map.of("kind", "findings_threshold", "maxAgeDays", 7, "scopes", List.of("builtin:sast"),
                    "thresholds", Map.of("medium", Map.of("minResolvedRatio", 0.6))));
            scan(first, hoursAgo(2), "sast,quality", null, true);
            scan(second, hoursAgo(2), "sast,quality", null, true);
            issue(first, "sast", null, "medium", "resolved", "under_review");
            issue(second, "sast", null, "medium", "resolved", "under_review");
            issue(second, "sast", null, "medium", "open", "under_review");
            open(developer, project);
            JsonNode measurement = measurements(developer, project, 1).at("/lines/0/measurement");
            assertThat(measurement.at("/outcome").asText()).as("2 of 3 resolved, at least 60 %").isEqualTo("pass");
            assertThat(total(measurement, "medium").at("/resolved").asLong()).isEqualTo(2);
        }
    }

    // ------------------------------------------------------------------ the other kinds

    @Nested
    @DisplayName("the other kinds")
    class Kinds {

        @Test
        @DisplayName("dependency analysis: a stored SBOM, and when asked a schedule at least as often as the age")
        void dependencies() throws Exception {
            publishWithRule(Map.of("kind", "dependency_analysis", "maxAgeDays", 7, "requireSchedule", true));
            scan(first, hoursAgo(2), "vulnerability,license", null, true);
            scan(second, hoursAgo(2), "vulnerability", null, false);
            open(developer, project);
            JsonNode measurement = measurements(developer, project, 1).at("/lines/0/measurement");
            assertThat(measurement.at("/outcome").asText()).isEqualTo("fail");
            assertThat(repository(measurement, second).at("/detail").asText()).contains("no SBOM");

            scan(second, hoursAgo(1), "vulnerability", null, true);
            assertThat(measurements(developer, project, 1).at("/lines/0/measurement/outcome").asText()).isEqualTo("pass");

            RepositoryEntity weekly = repositories.findById(first).orElseThrow();
            weekly.setScanIntervalMinutes(8 * 24 * 60);
            repositories.save(weekly);
            JsonNode unscheduled = measurements(developer, project, 1).at("/lines/0/measurement");
            assertThat(unscheduled.at("/outcome").asText()).isEqualTo("fail");
            assertThat(repository(unscheduled, first).at("/detail").asText()).contains("not scheduled at least every 7 days");
        }

        @Test
        @DisplayName("component versions: every declared package present at an allowed version, on every repository")
        void componentVersions() throws Exception {
            publishWithRule(Map.of("kind", "component_versions", "maxAgeDays", 7, "components",
                    List.of(Map.of("purlPrefix", "pkg:maven/com.example/ledger-core", "versions", List.of("3.2.1")))));
            long one = scan(first, hoursAgo(2), "vulnerability", null, true);
            long two = scan(second, hoursAgo(2), "vulnerability", null, true);
            component(one, "ledger-core", "3.2.1", "pkg:maven/com.example/ledger-core@3.2.1");
            component(two, "ledger-core", "2.0.0", "pkg:maven/com.example/ledger-core@2.0.0");
            open(developer, project);
            JsonNode measurement = measurements(developer, project, 1).at("/lines/0/measurement");
            assertThat(measurement.at("/outcome").asText()).isEqualTo("fail");
            assertThat(repository(measurement, second).at("/detail").asText()).contains("2.0.0, not an allowed version");

            long newer = scan(second, hoursAgo(1), "vulnerability", null, true);
            component(newer, "ledger-core", "3.2.1", "pkg:maven/com.example/ledger-core@3.2.1");
            assertThat(measurements(developer, project, 1).at("/lines/0/measurement/outcome").asText()).isEqualTo("pass");
        }

        @Test
        @DisplayName("coverage: the newest import of each repository, its ratio at least the minimum")
        void coverage() throws Exception {
            publishWithRule(Map.of("kind", "coverage_threshold", "maxAgeDays", 7, "metric", "line", "minimumRatio", 0.8,
                    "aggregation", "per_repository"));
            coverageImport(first, 90, 100, hoursAgo(1));
            open(developer, project);
            assertThat(measurements(developer, project, 1).at("/lines/0/measurement/reason").asText())
                    .isEqualTo("never_examined");

            coverageImport(second, 70, 100, hoursAgo(1));
            JsonNode under = measurements(developer, project, 1).at("/lines/0/measurement");
            assertThat(under.at("/outcome").asText()).isEqualTo("fail");
            assertThat(repository(under, second).at("/source").asText()).isEqualTo("coverage_import");

            coverageImport(second, 85, 100, hoursAgo(0));
            assertThat(measurements(developer, project, 1).at("/lines/0/measurement/outcome").asText()).isEqualTo("pass");
        }

        @Test
        @DisplayName("test reports: a matching suite, enough tests run, none failed")
        void testReports() throws Exception {
            publishWithRule(Map.of("kind", "test_suite_passed", "maxAgeDays", 7, "suitePattern", "com.example.arch.*",
                    "minimumTests", 2));
            testReport(first, hoursAgo(1), "com.example.arch.LayersTest", 3, 0);
            testReport(second, hoursAgo(1), "com.example.AppTest", 5, 0);
            open(developer, project);
            assertThat(measurements(developer, project, 1).at("/lines/0/measurement/reason").asText())
                    .isEqualTo("suite_not_found");

            testReport(second, hoursAgo(0), "com.example.arch.CyclesTest", 2, 1);
            assertThat(measurements(developer, project, 1).at("/lines/0/measurement/outcome").asText()).isEqualTo("fail");

            testReport(second, hoursAgo(0), "com.example.arch.CyclesTest", 2, 0);
            assertThat(measurements(developer, project, 1).at("/lines/0/measurement/outcome").asText()).isEqualTo("pass");
        }
    }

    // ------------------------------------------------------------------ relied on

    @Nested
    @DisplayName("what relies on a measurement")
    class ReliedOn {

        @Test
        @DisplayName("an answer rests on the measurement read, stored with it, and not on one that moved")
        void anAnswerRestsOnWhatWasRead() throws Exception {
            publishWithRule(SECRETS);
            scan(first, hoursAgo(2), "secret", null, true);
            scan(second, hoursAgo(2), "secret", null, true);
            open(developer, project);
            long line = itemIds(read(developer, 1)).getFirst();
            String digest = measurements(developer, project, 1).at("/lines/0/measurement/evidenceDigest").asText();

            issue(first, "secret", null, "high", "open", "under_review");
            MvcResult moved = answer(developer, 1, line, "yes", null, digest, edition()).andExpect(status().isConflict())
                    .andReturn();
            assertThat(typeOf(moved)).isEqualTo(PROBLEM + "checklist-measurement-changed");
            assertThat(json.readTree(moved.getResponse().getContentAsString()).at("/lines/0/outcome").asText())
                    .isEqualTo("fail");
            assertThat(answers.findAll()).isEmpty();

            String now = measurements(developer, project, 1).at("/lines/0/measurement/evidenceDigest").asText();
            JsonNode answered = read(answer(developer, 1, line, "no", "A leaked key is being rotated.", now, edition())
                    .andExpect(status().isCreated()));
            long measurementId = answered.at("/lines/0/answer/measurementId").asLong();
            assertThat(measurements.findById(measurementId)).hasValueSatisfying(row -> {
                assertThat(row.getPurpose()).isEqualTo("answer");
                assertThat(row.getOutcome()).isEqualTo("fail");
                assertThat(row.getEvidenceDigest()).isEqualTo(now);
                assertThat(row.getReconciliation()).isEqualTo("consistent");
            });
            assertThat(entries("CHECKLIST_ANSWERED")).singleElement()
                    .satisfies(entry -> assertThat(entry.getDescription()).contains("resting on its measurement — fail"));

            long unbound = itemIds(read(developer, 1)).get(1);
            assertThat(detailOf(answer(developer, 1, unbound, "yes", null, now, edition())
                    .andExpect(status().isBadRequest()).andReturn())).contains("measured by no rule");
        }

        @Test
        @DisplayName("the submission refuses a yes against a failure, and asks a yes without data for a comment and a proof")
        void theSubmissionReconciles() throws Exception {
            publishWithRule(SECRETS);
            scan(first, hoursAgo(2), "secret", null, true);
            open(developer, project);
            List<Long> lines = itemIds(read(developer, 1));
            answerAll(lines);

            // Line 1 has no data (the second repository was never scanned): a yes needs its comment and a proof.
            MvcResult unmeasured = submit(developer, 1, edition()).andExpect(status().isConflict()).andReturn();
            assertThat(typeOf(unmeasured)).isEqualTo(PROBLEM + "checklist-incomplete");
            assertThat(json.readTree(unmeasured.getResponse().getContentAsString()).at("/lines/0/problems").toString())
                    .contains("comment_required").contains("evidence_required");
            assertThat(measurements(developer, project, 1).at("/lines/0/problems").toString())
                    .as("what the measurements route names before a submission")
                    .contains("comment_required").contains("evidence_required");

            // Measured, and failing: a yes is contradicted, refused whatever its comment.
            scan(second, hoursAgo(1), "secret", null, true);
            issue(second, "secret", null, "critical", "open", "under_review");
            MvcResult contradicted = submit(developer, 1, edition()).andExpect(status().isConflict()).andReturn();
            assertThat(typeOf(contradicted)).isEqualTo(PROBLEM + "checklist-measurement-contradicted");
            JsonNode problem = json.readTree(contradicted.getResponse().getContentAsString());
            assertThat(problem.at("/lines/0/itemId").asLong()).isEqualTo(lines.getFirst());
            assertThat(problem.at("/lines/0/answer").asText()).isEqualTo("yes");
            assertThat(problem.at("/lines/0/outcome").asText()).isEqualTo("fail");
            assertThat(measurements.findAll()).as("a refused submission stores nothing").isEmpty();

            // Answered no, with the reason: understated or consistent, the submission goes, measured.
            answer(developer, 1, lines.getFirst(), "no", "The leaked key is being rotated.", null, edition())
                    .andExpect(status().isCreated());
            submit(developer, 1, edition()).andExpect(status().isOk());
            assertThat(measurements.findAll()).singleElement().satisfies(row -> {
                assertThat(row.getPurpose()).isEqualTo("submission");
                assertThat(row.getAnswerValue()).isEqualTo("no");
                assertThat(row.getReconciliation()).isEqualTo("consistent");
                assertThat(row.getRuleKind()).isEqualTo("findings_threshold");
            });
            assertThat(entries("CHECKLIST_SUBMITTED")).singleElement()
                    .satisfies(entry -> assertThat(entry.getDescription()).contains("1 measured line: 1 fail"));
        }

        @Test
        @DisplayName("the read's readiness is the submission's: a failing measurement alone keeps a draft, on the line it names")
        void readinessIsTheSubmissions() throws Exception {
            publishWithRule(SECRETS);
            scan(first, hoursAgo(2), "secret", null, true);
            open(developer, project);
            List<Long> lines = itemIds(read(developer, 1));
            answerAll(lines);

            // A yes where there is no data (the second repository was never scanned): the read names what
            // the submission asks, before it is asked.
            JsonNode unmeasured = read(developer, 1);
            assertThat(unmeasured.at("/readyToSubmit").asBoolean()).isFalse();
            assertThat(unmeasured.at("/lines/0/problems").toString())
                    .isEqualTo("[\"comment_required\",\"evidence_required\"]");
            MvcResult incomplete = submit(developer, 1, edition()).andExpect(status().isConflict()).andReturn();
            assertThat(typeOf(incomplete)).isEqualTo(PROBLEM + "checklist-incomplete");
            assertThat(json.readTree(incomplete.getResponse().getContentAsString()).at("/lines/0/problems"))
                    .isEqualTo(unmeasured.at("/lines/0/problems"));

            // Measured, and failing. Every line answered, nothing asked of a proof: the failing measurement
            // is the only obstacle, and the read says so on the line the submission then names.
            scan(second, hoursAgo(1), "secret", null, true);
            issue(second, "secret", null, "critical", "open", "under_review");
            JsonNode draft = read(developer, 1);
            assertThat(draft.at("/readyToSubmit").asBoolean()).as("a yes against a failure is not ready").isFalse();
            assertThat(draft.at("/lines/0/itemId").asLong()).isEqualTo(lines.getFirst());
            assertThat(draft.at("/lines/0/problems").toString()).isEqualTo("[\"measurement_contradicted\"]");
            for (int line = 1; line < lines.size(); line++) {
                assertThat(draft.at("/lines/" + line + "/problems").isEmpty()).as("line %s", line + 1).isTrue();
            }
            MvcResult refused = submit(developer, 1, edition()).andExpect(status().isConflict()).andReturn();
            assertThat(typeOf(refused)).isEqualTo(PROBLEM + "checklist-measurement-contradicted");
            JsonNode problem = json.readTree(refused.getResponse().getContentAsString());
            assertThat(problem.at("/lines").size()).isEqualTo(1);
            assertThat(problem.at("/lines/0/itemId").asLong()).as("the line the read named").isEqualTo(lines.getFirst());

            // Ready once the read says so, and the submission agrees.
            answer(developer, 1, lines.getFirst(), "no", "The leaked key is being rotated.", null, edition())
                    .andExpect(status().isCreated());
            assertThat(read(developer, 1).at("/readyToSubmit").asBoolean()).isTrue();
            JsonNode submitted = read(submit(developer, 1, edition()).andExpect(status().isOk()));
            assertThat(submitted.at("/readyToSubmit").asBoolean()).as("past the draft, nothing is to submit").isFalse();
        }

        @Test
        @DisplayName("the evidence names each repository as every screen does, and none that has left the project")
        void theEvidenceNamesItsRepositories() throws Exception {
            publishWithRule(SECRETS);
            scan(first, hoursAgo(2), "secret", null, true);
            scan(second, hoursAgo(2), "secret", null, true);
            open(developer, project);
            answerAll(itemIds(read(developer, 1)));
            submit(developer, 1, edition()).andExpect(status().isOk());

            JsonNode live = measurements(developer, project, 1).at("/lines/0/measurement");
            assertThat(repository(live, first).at("/repositoryName").asText())
                    .isEqualTo(TargetNaming.of(repositories.findById(first).orElseThrow()));
            assertThat(repository(live, second).at("/repositoryName").asText())
                    .isEqualTo(TargetNaming.of(repositories.findById(second).orElseThrow()));
            JsonNode atSubmission = measurements(developer, project, 1).at("/lines/0/atSubmission");
            assertThat(repository(atSubmission, second).at("/repositoryName").asText()).isNotBlank();

            // The submission's stored evidence still cites the repository; the project no longer holds it.
            mvc.perform(authenticated(delete("/api/v1/projects/" + project + "/repositories/" + second), asAdmin()))
                    .andExpect(status().isNoContent());
            JsonNode after = measurements(developer, project, 1).at("/lines/0/atSubmission");
            assertThat(repository(after, second).at("/repositoryName").isNull())
                    .as("a name is handed out for the repositories the reader was judged by, only").isTrue();
            assertThat(repository(after, first).at("/repositoryName").asText()).isNotBlank();
        }

        @Test
        @DisplayName("a yes where there is no data goes with a comment and a proof, declared not measured")
        void declaredNotMeasured() throws Exception {
            publishWithRule(SECRETS);
            open(developer, project);
            List<Long> lines = itemIds(read(developer, 1));
            answerAll(lines);
            answer(developer, 1, lines.getFirst(), "yes", "Scanned by the vendor's pipeline.", null, edition())
                    .andExpect(status().isCreated());
            link(developer, 1, lines.getFirst(), "https://wiki.example.invalid/secrets-scan", edition());

            submit(developer, 1, edition()).andExpect(status().isOk());
            assertThat(measurements.findAll()).singleElement()
                    .satisfies(row -> assertThat(row.getReconciliation()).isEqualTo("declared_not_measured"));
        }

        @Test
        @DisplayName("a sign-off whose measurement changed after the submission is refused, and freezes one that did not")
        void theSignOffJudgesFreshnessAgain() throws Exception {
            publishWithRule(SECRETS);
            scan(first, hoursAgo(2), "secret", null, true);
            scan(second, hoursAgo(2), "secret", null, true);
            open(developer, project);
            answerAll(itemIds(read(developer, 1)));
            submit(developer, 1, edition()).andExpect(status().isOk());

            long leaked = issue(first, "secret", null, "critical", "open", "under_review");
            MvcResult refused = signOff(ciso, 1, edition()).andExpect(status().isConflict()).andReturn();
            assertThat(typeOf(refused)).isEqualTo(PROBLEM + "checklist-measurement-changed");
            JsonNode problem = json.readTree(refused.getResponse().getContentAsString());
            assertThat(problem.at("/lines/0/submittedOutcome").asText()).isEqualTo("pass");
            assertThat(problem.at("/lines/0/outcome").asText()).isEqualTo("fail");
            assertThat(entries("CHECKLIST_SIGN_OFF_REFUSED")).singleElement()
                    .satisfies(entry -> assertThat(entry.getDescription()).contains("a measurement changed since the submission"));
            assertThat(read(ciso, 1).at("/checklist/status").asText()).isEqualTo("submitted");

            IssueEntity row = issues.findById(leaked).orElseThrow();
            row.setTriageStatus("not_affected");
            issues.save(row);
            signOff(ciso, 1, edition()).andExpect(status().isOk());

            // Frozen: what the sign-off judged is what the revision says, whatever the backlog does next.
            issue(second, "secret", null, "critical", "open", "under_review");
            JsonNode frozen = measurements(developer, project, 1);
            assertThat(frozen.at("/live").asBoolean()).isFalse();
            assertThat(frozen.at("/lines/0/measurement/purpose").asText()).isEqualTo("sign_off");
            assertThat(frozen.at("/lines/0/measurement/outcome").asText()).isEqualTo("pass");
            assertThat(frozen.at("/lines/0/atSubmission/outcome").asText()).isEqualTo("pass");
            assertThat(frozen.at("/lines/0/reconciliation").asText()).isEqualTo("consistent");
        }
    }

    // ------------------------------------------------------------------ every measured line, as measured, at once

    @Nested
    @DisplayName("answering every measured line as measured")
    class AsMeasured {

        private static final Map<String, Object> SAST = Map.of("kind", "findings_threshold", "maxAgeDays", 7,
                "scopes", List.of("builtin:sast"), "thresholds", Map.of("critical", Map.of("maxOpen", 0)));

        private static final Map<String, Object> IAC = Map.of("kind", "findings_threshold", "maxAgeDays", 7,
                "scopes", List.of("builtin:iac"), "thresholds", Map.of("critical", Map.of("maxOpen", 0)));

        /** Four measured lines: secrets passing, static analysis failing, IaC never looked at, secrets again. */
        private List<Long> fourMeasuredLines() throws Exception {
            publishWithRules(ChecklistWorkbooks.SECOND, List.of(SECRETS, SAST, IAC, SECRETS));
            scan(first, hoursAgo(2), "secret,sast", null, true);
            scan(second, hoursAgo(2), "secret,sast", null, true);
            issue(first, "sast", null, "critical", "open", "under_review");
            open(developer, project);
            return itemIds(read(developer, 1));
        }

        @Test
        @DisplayName("a pass is answered yes by the caller, resting on its measurement; a fail, no data and an answer are left alone")
        void passesAreAnsweredAndTheRestIsLeftAlone() throws Exception {
            List<Long> lines = fourMeasuredLines();
            answer(developer, 1, lines.get(3), "no", "The vault migration is not finished.", null, edition())
                    .andExpect(status().isCreated());
            int before = edition();

            JsonNode done = read(asMeasured(ciso, 1, before, shownPassing()).andExpect(status().isOk()));

            assertThat(done.at("/checklist/checklist/edition").asInt()).as("one act, one edition").isEqualTo(before + 1);
            assertThat(done.at("/answered")).hasSize(1);
            JsonNode given = done.at("/answered/0");
            assertThat(given.at("/itemId").asLong()).isEqualTo(lines.get(0));
            assertThat(given.at("/value").asText()).isEqualTo("yes");
            assertThat(done.at("/checklist/lines/0/answer/answeredBy").asText()).isEqualTo(ciso.name());
            assertThat(done.at("/checklist/lines/0/answer/measurementId").asLong())
                    .isEqualTo(given.at("/measurementId").asLong());

            Map<Long, JsonNode> skipped = new LinkedHashMap<>();
            done.at("/skipped").forEach(line -> skipped.put(line.at("/itemId").asLong(), line));
            assertThat(skipped.keySet()).containsExactly(lines.get(1), lines.get(2), lines.get(3));
            assertThat(skipped.get(lines.get(1)).at("/reason").asText()).isEqualTo("needs_comment");
            assertThat(skipped.get(lines.get(1)).at("/outcome").asText()).isEqualTo("fail");
            assertThat(skipped.get(lines.get(2)).at("/reason").asText()).isEqualTo("no_data");
            assertThat(skipped.get(lines.get(2)).at("/noDataReason").asText()).isEqualTo("step_absent");
            assertThat(skipped.get(lines.get(3)).at("/reason").asText()).isEqualTo("already_answered");
            assertThat(skipped.get(lines.get(3)).at("/outcome").asText()).as("passing, and still left alone")
                    .isEqualTo("pass");
            assertThat(skipped.get(lines.get(3)).at("/answer").asText()).isEqualTo("no");
            assertThat(skipped.get(lines.get(1)).at("/evidenceDigest").asText()).as("the digest it has now").hasSize(64);

            // The answer is the caller's, a row of the line's history, resting on the measurement stored with it.
            assertThat(answers.findAll()).filteredOn(row -> row.getItemId().equals(lines.get(0))).singleElement()
                    .satisfies(row -> {
                        assertThat(row.getAnsweredBy()).isEqualTo(ciso.name());
                        assertThat(row.getAnsweredById()).isEqualTo(ciso.id());
                        assertThat(row.getValue()).isEqualTo("yes");
                        assertThat(row.getComment()).isNull();
                        assertThat(row.getEdition()).isEqualTo(before + 1);
                        assertThat(row.getId()).isEqualTo(given.at("/answerId").asLong());
                    });
            assertThat(measurements.findById(given.at("/measurementId").asLong())).hasValueSatisfying(row -> {
                assertThat(row.getPurpose()).isEqualTo("answer");
                assertThat(row.getOutcome()).isEqualTo("pass");
                assertThat(row.getAnswerValue()).isEqualTo("yes");
                assertThat(row.getComputedBy()).isEqualTo(ciso.name());
                assertThat(row.getEvidenceDigest()).isEqualTo(given.at("/evidenceDigest").asText());
            });
            assertThat(measurements.findAll()).as("only the answered line's measurement is stored").hasSize(1);
            JsonNode history = read(mvc.perform(authenticated(
                    get(base(project) + "/1/items/" + lines.get(0) + "/history"), developer.token())).andExpect(status().isOk()));
            assertThat(history.at("/answers")).singleElement().satisfies(row -> {
                assertThat(row.at("/answeredBy").asText()).isEqualTo(ciso.name());
                assertThat(row.at("/measurementId").asLong()).isEqualTo(given.at("/measurementId").asLong());
            });

            // A person's answer is never replaced; the failing and the unmeasured lines stay unanswered.
            assertThat(answers.findAll()).filteredOn(row -> row.getItemId().equals(lines.get(3))).singleElement()
                    .satisfies(row -> assertThat(row.getAnsweredBy()).isEqualTo(developer.name()));
            assertThat(answers.findAll()).noneMatch(row -> row.getItemId().equals(lines.get(1))
                    || row.getItemId().equals(lines.get(2)));

            assertThat(entries("CHECKLIST_ANSWERED")).filteredOn(entry -> entry.getDescription().contains("in one act"))
                    .singleElement().satisfies(entry -> {
                        assertThat(entry.getUserId()).isEqualTo(ciso.name());
                        assertThat(entry.getDescription()).contains("line 1 ").contains("resting on its measurement — pass");
                    });
        }

        @Test
        @DisplayName("with nothing left to answer, nothing is written and the edition stays")
        void nothingToAnswer() throws Exception {
            List<Long> lines = fourMeasuredLines();
            answer(developer, 1, lines.get(0), "yes", null, null, edition()).andExpect(status().isCreated());
            answer(developer, 1, lines.get(3), "yes", null, null, edition()).andExpect(status().isCreated());
            int before = edition();
            JsonNode done = read(asMeasured(ciso, 1, before, shownPassing()).andExpect(status().isOk()));
            assertThat(done.at("/answered")).isEmpty();
            assertThat(done.at("/skipped")).hasSize(4);
            assertThat(edition()).isEqualTo(before);
            assertThat(answers.findAll()).hasSize(2);
            assertThat(measurements.findAll()).isEmpty();
        }

        @Test
        @DisplayName("a stale edition is refused and writes nothing; no edition is a bad request")
        void aStaleEdition() throws Exception {
            List<Long> lines = fourMeasuredLines();
            int read = edition();
            answer(developer, 1, lines.get(3), "no", "Being migrated.", null, read).andExpect(status().isCreated());

            MvcResult stale = asMeasured(ciso, 1, read, shownPassing()).andExpect(status().isConflict()).andReturn();
            assertThat(typeOf(stale)).isEqualTo(PROBLEM + "checklist-changed");
            assertThat(answers.findAll()).singleElement()
                    .satisfies(row -> assertThat(row.getItemId()).isEqualTo(lines.get(3)));
            assertThat(measurements.findAll()).isEmpty();
            assertThat(entries("CHECKLIST_ANSWERED")).hasSize(1);

            // With nothing left to answer nothing would be written, and the edition read is still judged.
            answer(developer, 1, lines.get(0), "yes", null, null, edition()).andExpect(status().isCreated());
            assertThat(typeOf(asMeasured(ciso, 1, read, shownPassing()).andExpect(status().isConflict()).andReturn()))
                    .isEqualTo(PROBLEM + "checklist-changed");

            asMeasured(ciso, 1, null, shownPassing()).andExpect(status().isBadRequest());
            assertThat(detailOf(asMeasured(ciso, 1, edition(), null).andExpect(status().isBadRequest()).andReturn()))
                    .as("the measurements shown are required").contains("measurements you were shown");
            assertThat(detailOf(asMeasured(ciso, 1, edition(), Map.of(lines.get(0), "0".repeat(64), 999_999L, "x"))
                    .andExpect(status().isBadRequest()).andReturn())).contains("no line 999999");
        }

        @Test
        @DisplayName("a submitted revision is not answered")
        void aSubmittedRevision() throws Exception {
            publishWithRule(SECRETS);
            scan(first, hoursAgo(2), "secret", null, true);
            scan(second, hoursAgo(2), "secret", null, true);
            open(developer, project);
            answerAll(itemIds(read(developer, 1)));
            submit(developer, 1, edition()).andExpect(status().isOk());
            long answered = answers.count();

            MvcResult refused = asMeasured(ciso, 1, edition(), Map.of()).andExpect(status().isConflict()).andReturn();
            assertThat(typeOf(refused)).isEqualTo(PROBLEM + "checklist-not-draft");
            assertThat(answers.count()).isEqualTo(answered);
        }

        @Test
        @DisplayName("a partial reader is answered as if the project did not exist; an auditor may not answer")
        void whoMayAnswer() throws Exception {
            fourMeasuredLines();
            int edition = edition();
            Map<Long, String> shown = shownPassing();
            settings.set(Setting.TARGET_VISIBILITY, VisibilityMode.ASSIGNED.wireName());
            Account partial = account(Role.USER);
            grant(partial.id(), "repository", first);
            assertThat(detailOf(asMeasured(partial, 1, edition, shown).andExpect(status().isNotFound()).andReturn()))
                    .isEqualTo("Project not found.");

            Account auditor = account(Role.AUDITOR);
            asMeasured(auditor, 1, edition, shown).andExpect(status().isForbidden());
            assertThat(answers.findAll()).isEmpty();

            grant(partial.id(), "repository", second);
            asMeasured(partial, 1, edition, shown).andExpect(status().isOk());
            assertThat(answers.findAll()).as("the two passing lines, under the caller's name").hasSize(2)
                    .allSatisfy(row -> assertThat(row.getAnsweredBy()).isEqualTo(partial.name()));
        }

        @Test
        @DisplayName("a line whose evidence is not the one shown is left alone, even passing, and says what it is now")
        void aMeasurementThatMoved() throws Exception {
            List<Long> lines = fourMeasuredLines();
            Map<Long, String> shown = shownPassing();
            // A scan since the read: the secrets lines still pass, on evidence the person never saw.
            scan(second, hoursAgo(1), "secret,sast", null, true);

            JsonNode done = read(asMeasured(ciso, 1, edition(), shown).andExpect(status().isOk()));
            assertThat(done.at("/answered")).isEmpty();
            JsonNode moved = skipOf(done, lines.get(0));
            assertThat(moved.at("/reason").asText()).isEqualTo("measurement_changed");
            assertThat(moved.at("/outcome").asText()).isEqualTo("pass");
            assertThat(moved.at("/evidenceDigest").asText()).isNotEqualTo(shown.get(lines.get(0)))
                    .isEqualTo(measurements(developer, project, 1).at("/lines/0/measurement/evidenceDigest").asText());
            assertThat(answers.findAll()).isEmpty();
            assertThat(measurements.findAll()).isEmpty();
            assertThat(entries("CHECKLIST_ANSWERED")).isEmpty();
        }

        @Test
        @DisplayName("a passing line the person was not shown is left alone")
        void aLineNotShown() throws Exception {
            List<Long> lines = fourMeasuredLines();
            Map<Long, String> shown = shownPassing();
            shown.remove(lines.get(3));

            JsonNode done = read(asMeasured(ciso, 1, edition(), shown).andExpect(status().isOk()));
            assertThat(done.at("/answered")).singleElement()
                    .satisfies(line -> assertThat(line.at("/itemId").asLong()).isEqualTo(lines.get(0)));
            assertThat(skipOf(done, lines.get(3)).at("/reason").asText()).isEqualTo("not_shown");
            assertThat(skipOf(done, lines.get(3)).at("/outcome").asText()).isEqualTo("pass");
            assertThat(answers.findAll()).singleElement()
                    .satisfies(row -> assertThat(row.getItemId()).isEqualTo(lines.get(0)));
        }

        /** What the screen offers the one click on: each passing line's itemId and the digest it read. */
        private Map<Long, String> shownPassing() throws Exception {
            Map<Long, String> shown = new LinkedHashMap<>();
            measurements(developer, project, 1).at("/lines").forEach(line -> {
                if (line.at("/measurement/outcome").asText().equals("pass")) {
                    shown.put(line.at("/itemId").asLong(), line.at("/measurement/evidenceDigest").asText());
                }
            });
            return shown;
        }

        private JsonNode skipOf(JsonNode done, long itemId) {
            for (JsonNode line : done.at("/skipped")) {
                if (line.at("/itemId").asLong() == itemId) {
                    return line;
                }
            }
            throw new AssertionError("Line " + itemId + " was not skipped: " + done.at("/skipped"));
        }

        private ResultActions asMeasured(Account who, int revision, Integer edition, Map<Long, String> shown)
                throws Exception {
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("edition", edition);
            if (shown != null) {
                List<Map<String, Object>> lines = new ArrayList<>();
                shown.forEach((itemId, digest) -> lines.add(Map.of("itemId", itemId, "measurementDigest", digest)));
                body.put("lines", lines);
            }
            return send(who, base(project) + "/" + revision + "/answers/as-measured", body);
        }
    }

    // ------------------------------------------------------------------ who may read them

    @Test
    @DisplayName("a partial reader is answered as if the project did not exist, on the measurements and the answer resting on one")
    void aPartialReaderIsAnsweredNotFound() throws Exception {
        publishWithRule(SECRETS);
        open(developer, project);
        long line = itemIds(read(developer, 1)).getFirst();
        settings.set(Setting.TARGET_VISIBILITY, VisibilityMode.ASSIGNED.wireName());
        Account partial = account(Role.USER);
        grant(partial.id(), "repository", first);

        MvcResult hidden = mvc.perform(authenticated(get(base(project) + "/1/measurements"), partial.token()))
                .andExpect(status().isNotFound()).andReturn();
        assertThat(detailOf(hidden)).isEqualTo("Project not found.");
        assertThat(detailOf(answer(partial, 1, line, "yes", null, "0".repeat(64), 1).andExpect(status().isNotFound())
                .andReturn())).isEqualTo("Project not found.");
        mvc.perform(get(base(project) + "/1/measurements")).andExpect(status().isUnauthorized());

        grant(partial.id(), "repository", second);
        mvc.perform(authenticated(get(base(project) + "/1/measurements"), partial.token())).andExpect(status().isOk());
    }

    @Test
    @DisplayName("the view crosses the wire through the application's mapper and reads back whole")
    void theWire() throws Exception {
        publishWithRule(SECRETS);
        scan(first, hoursAgo(2), "secret", null, true);
        open(developer, project);
        MvcResult result = mvc.perform(authenticated(get(base(project) + "/1/measurements"), developer.token()))
                .andExpect(status().isOk()).andReturn();
        String body = result.getResponse().getContentAsString();

        ChecklistMeasurementsView view = json.readValue(body, ChecklistMeasurementsView.class);
        assertThat(view.live()).isTrue();
        assertThat(view.lines()).singleElement().satisfies(line -> {
            assertThat(line.rule().scopes()).containsExactly("builtin:secret");
            assertThat(line.measurement().evidence().repositories()).hasSize(2);
            assertThat(line.measurement().asOf()).isNotNull();
        });
        assertThat(json.readTree(json.writeValueAsString(view))).isEqualTo(json.readTree(body));
        assertThat(json.readTree(body).at("/lines/0/measurement/asOf").asText()).as("an instant, as text")
                .matches("\\d{4}-\\d{2}-\\d{2}T.*Z");
        assertThat(read(developer, 1).at("/lines/0/rule/kind").asText()).as("the line's own view names its rule")
                .isEqualTo("findings_threshold");
    }

    // ------------------------------------------------------------------ helpers

    private String base(long projectId) {
        return "/api/v1/projects/" + projectId + "/checklists";
    }

    private Account account(Role role) {
        String name = role.name().toLowerCase(java.util.Locale.ROOT) + "-" + System.nanoTime();
        String token = tokenFor(name, role, false);
        return new Account(token, users.findByUsername(name).orElseThrow().getId(), name);
    }

    private long project(String name) throws Exception {
        long solution = idOf(mvc.perform(authenticated(post("/api/v1/solutions"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON).content(write(Map.of("name", name + " " + System.nanoTime()))))
                .andExpect(status().isCreated()));
        return idOf(mvc.perform(authenticated(post("/api/v1/solutions/" + solution + "/projects"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON).content(write(Map.of("name", name))))
                .andExpect(status().isCreated()));
    }

    private long repository(String url, Integer intervalMinutes) {
        RepositoryEntity entity = new RepositoryEntity();
        entity.setUrl(url);
        entity.setName(url.substring(url.lastIndexOf('/') + 1));
        entity.setBranch("main");
        entity.setScanIntervalMinutes(intervalMinutes);
        return repositories.save(entity).getId();
    }

    private void file(long projectId, long repositoryId) throws Exception {
        mvc.perform(authenticated(put("/api/v1/projects/" + projectId + "/repositories/" + repositoryId), asAdmin()))
                .andExpect(status().isNoContent());
    }

    private void grantAll() {
        settings.set(Setting.TARGET_VISIBILITY, VisibilityMode.EVERYONE.wireName());
    }

    private void grant(long userId, String kind, long id) throws Exception {
        List<Map<String, Object>> held = new ArrayList<>();
        read(mvc.perform(authenticated(get("/api/v1/users/" + userId + "/targets"), asAdmin())).andExpect(status().isOk()))
                .forEach(grant -> held.add(Map.of("kind", grant.at("/kind").asText(), "id", grant.at("/id").asLong())));
        held.add(Map.of("kind", kind, "id", id));
        mvc.perform(authenticated(put("/api/v1/users/" + userId + "/targets"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON).content(write(held)))
                .andExpect(status().isOk());
    }

    /** The first template, its first line bound to {@code rule}, published — as an administrator, four-eyes off. */
    private void publishWithRule(Map<String, Object> rule) throws Exception {
        publishWithRules(ChecklistWorkbooks.FIRST, List.of(rule));
    }

    /**
     * A template of {@code lines}, its first lines bound to {@code rules} in order, published — as an
     * administrator, four-eyes off.
     */
    private void publishWithRules(List<ChecklistWorkbooks.Line> lines, List<Map<String, Object>> rules) throws Exception {
        mvc.perform(authenticated(post(TEMPLATES + "/release/versions"), asAdmin())
                        .contentType(MediaType.APPLICATION_OCTET_STREAM).content(ChecklistWorkbooks.of(lines)))
                .andExpect(status().isCreated());
        JsonNode laid = read(mvc.perform(authenticated(put(TEMPLATES + "/release/versions/1/layout"), asAdmin())
                        .param("revision", "1")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(layout(ChecklistWorkbooks.FIRST_ITEM_ROW + lines.size() - 1))))
                .andExpect(status().isOk()));
        List<Map<String, Object>> bindings = new ArrayList<>();
        for (int i = 0; i < rules.size(); i++) {
            Map<String, Object> line = new LinkedHashMap<>();
            line.put("itemKey", laid.at("/items/" + i + "/itemKey").asText());
            line.put("rule", rules.get(i));
            bindings.add(line);
        }
        JsonNode bound = read(mvc.perform(authenticated(put(TEMPLATES + "/release/versions/1/rules"), asAdmin())
                        .param("revision", String.valueOf(laid.at("/version/revision").asInt()))
                        .contentType(MediaType.APPLICATION_JSON).content(write(Map.of("items", bindings))))
                .andExpect(status().isOk()));
        mvc.perform(authenticated(post(TEMPLATES + "/release/versions/1/publish"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"revision\":" + bound.at("/version/revision").asInt() + "}"))
                .andExpect(status().isOk());
    }

    private static Map<String, Object> layout(int lastItemRow) {
        Map<String, Object> layout = new LinkedHashMap<>();
        layout.put("sheet", "Checklist");
        layout.put("columns", Map.of("domain", "A", "objective", "B", "control", "C", "contact", "D", "kpi", "E",
                "answer", "F", "comment", "G"));
        layout.put("firstItemRow", ChecklistWorkbooks.FIRST_ITEM_ROW);
        layout.put("lastItemRow", lastItemRow);
        layout.put("header", Map.of(
                "date", Map.of("label", "A2", "value", "B2"),
                "product", Map.of("label", "A3", "value", "B3"),
                "author", Map.of("label", "A4", "value", "B4")));
        layout.put("answers", Map.of("yes", "Done", "no", "Not done"));
        return layout;
    }

    private void open(Account who, long projectId) throws Exception {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("template", "release");
        body.put("version", 1);
        body.put("edition", null);
        send(who, base(projectId), body).andExpect(status().isCreated());
    }

    private JsonNode measurements(Account who, long projectId, int revision) throws Exception {
        return read(mvc.perform(authenticated(get(base(projectId) + "/" + revision + "/measurements"), who.token()))
                .andExpect(status().isOk()));
    }

    private ResultActions answer(Account who, int revision, long item, String value, String comment, String digest,
            Integer edition) throws Exception {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("value", value);
        body.put("comment", comment);
        body.put("measurementDigest", digest);
        body.put("edition", edition);
        return send(who, base(project) + "/" + revision + "/items/" + item + "/answers", body);
    }

    /** Every line answered yes by the developer, each at the edition just read. */
    private void answerAll(List<Long> lines) throws Exception {
        for (long line : lines) {
            answer(developer, 1, line, "yes", null, null, edition()).andExpect(status().isCreated());
        }
    }

    private void link(Account who, int revision, long item, String link, int edition) throws Exception {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("link", link);
        body.put("performedOn", LocalDate.now(ZoneOffset.UTC).toString());
        body.put("edition", edition);
        send(who, base(project) + "/" + revision + "/items/" + item + "/evidence/links", body)
                .andExpect(status().isCreated());
    }

    private ResultActions submit(Account who, int revision, Integer edition) throws Exception {
        return send(who, base(project) + "/" + revision + "/submission", Map.of("edition", edition));
    }

    private ResultActions signOff(Account who, int revision, Integer edition) throws Exception {
        return send(who, base(project) + "/" + revision + "/sign-off", Map.of("edition", edition));
    }

    private ResultActions send(Account who, String path, Map<String, ?> body) throws Exception {
        return mvc.perform(authenticated(post(path), who.token())
                .contentType(MediaType.APPLICATION_JSON).content(write(body)));
    }

    private JsonNode read(Account who, int revision) throws Exception {
        return read(mvc.perform(authenticated(get(base(project) + "/" + revision), who.token())).andExpect(status().isOk()));
    }

    private int edition() throws Exception {
        return read(developer, 1).at("/checklist/edition").asInt();
    }

    private static List<Long> itemIds(JsonNode view) {
        List<Long> ids = new ArrayList<>();
        view.at("/lines").forEach(line -> ids.add(line.at("/itemId").asLong()));
        return ids;
    }

    private static String statusOf(JsonNode measurement, long repositoryId) {
        return repository(measurement, repositoryId).at("/status").asText();
    }

    private static JsonNode repository(JsonNode measurement, long repositoryId) {
        for (JsonNode line : measurement.at("/evidence/repositories")) {
            if (line.at("/repositoryId").asLong() == repositoryId) {
                return line;
            }
        }
        throw new AssertionError("No evidence for repository " + repositoryId + " in " + measurement);
    }

    private static JsonNode total(JsonNode measurement, String severity) {
        for (JsonNode figure : measurement.at("/evidence/figures")) {
            if (figure.at("/scope").asText().equals("all") && figure.at("/severity").asText().equals(severity)) {
                return figure;
            }
        }
        throw new AssertionError("No total for " + severity + " in " + measurement);
    }

    private static Instant hoursAgo(int hours) {
        return Instant.now().minus(Duration.ofHours(hours)).minusSeconds(1);
    }

    private long scan(long repositoryId, Instant createdAt, String examinedTypes, String pluginSteps, boolean sbom) {
        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repositoryId);
        scan.setBranch("main");
        scan.setStatus(ScanStatus.COMPLETED.wireName());
        scan.setCreatedAt(createdAt);
        scan.setAttempts(1);
        scan.setExaminedTypes(examinedTypes);
        scan.setPluginSteps(pluginSteps);
        scan.setSbom(sbom ? "{\"artifacts\":[]}" : null);
        return scans.save(scan).getId();
    }

    /** A scan's plugin steps as the ingestor writes them: one outcome, its state one of decision 0017's three. */
    private static String plugin(String id, String state) {
        return "[{\"pluginId\":\"" + id + "\",\"manifestDigest\":\"sha256:" + "a".repeat(64) + "\",\"state\":\"" + state
                + "\",\"findings\":" + (state.equals("produced") ? "0" : "null") + ",\"languages\":[],\"reason\":null}]";
    }

    private long issue(long repositoryId, String type, String tool, String severity, String state, String triage) {
        IssueEntity issue = new IssueEntity();
        issue.setRepoId(repositoryId);
        byte[] fingerprint = new byte[32];
        ThreadLocalRandom.current().nextBytes(fingerprint);
        issue.setFingerprint(HexFormat.of().formatHex(fingerprint));
        issue.setType(type);
        issue.setTool(tool);
        issue.setIdentifier("rule-" + System.nanoTime());
        issue.setSeverity(severity);
        issue.setState(state);
        issue.setTriageStatus(triage);
        issue.setFirstSeenAt(Instant.now().minus(Duration.ofDays(3)));
        issue.setLastSeenAt(Instant.now());
        issue.setTimesSeen(1);
        return issues.save(issue).getId();
    }

    private void component(long scanId, String name, String version, String purl) {
        ComponentEntity component = new ComponentEntity();
        component.setScanId(scanId);
        component.setName(name);
        component.setVersion(version);
        component.setPurl(purl);
        components.save(component);
    }

    private long sarifImport(long repositoryId, String toolKeys, Instant at) {
        SarifImportEntity row = new SarifImportEntity();
        row.setSourceId(1L);
        row.setSourceSlug("ledger-ci");
        row.setRepoId(repositoryId);
        row.setTools("ESLint 9.1.0");
        row.setToolKeys(toolKeys);
        row.setDocumentSha256("b".repeat(64));
        row.setImportedAt(at);
        row.setImportedBy("pipeline");
        row.setApiKeyId(UUID.randomUUID());
        return sarifImports.save(row).getId();
    }

    private void coverageImport(long repositoryId, long covered, long total, Instant at) {
        CoverageImportEntity row = new CoverageImportEntity();
        row.setSourceId(1L);
        row.setSourceSlug("ledger-ci");
        row.setRepoId(repositoryId);
        row.setFormat("jacoco");
        row.setLinesCovered(covered);
        row.setLinesTotal(total);
        row.setDocumentSha256("c".repeat(64));
        row.setImportedAt(at);
        row.setImportedBy("pipeline");
        row.setApiKeyId(UUID.randomUUID());
        coverageImports.save(row);
    }

    private void testReport(long repositoryId, Instant at, String suite, int tests, int failures) {
        TestReportImportEntity row = new TestReportImportEntity();
        row.setSourceId(1L);
        row.setSourceSlug("ledger-ci");
        row.setRepoId(repositoryId);
        row.setFormat("junit");
        row.setDocumentsCount(1);
        row.setSuitesCount(1);
        row.setTestsCount(tests);
        row.setFailuresCount(failures);
        row.setDocumentSha256("d".repeat(64));
        row.setImportedAt(at);
        row.setImportedBy("pipeline");
        row.setApiKeyId(UUID.randomUUID());
        long id = testReports.save(row).getId();
        TestSuiteResultEntity result = new TestSuiteResultEntity();
        result.setImportId(id);
        result.setName(suite);
        result.setTestsCount(tests);
        result.setFailuresCount(failures);
        suites.save(result);
    }

    private String typeOf(MvcResult result) throws Exception {
        return json.readTree(result.getResponse().getContentAsString()).path("type").asText();
    }

    private long idOf(ResultActions result) throws Exception {
        return read(result).path("id").asLong();
    }

    private JsonNode read(ResultActions result) throws Exception {
        return json.readTree(result.andReturn().getResponse().getContentAsString());
    }

    private List<AuditLogEntity> entries(String operation) {
        return auditLog.findAll().stream().filter(entry -> operation.equals(entry.getOperationType())).toList();
    }
}
