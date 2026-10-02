package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.asyncDispatch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.access.persistence.UserRepository;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogEntity;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogRepository;
import com.asmolabs.vectispire.core.checklists.ProjectChecklistService;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistAnswerEntity;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistAnswerRepository;
import com.asmolabs.vectispire.core.maintenance.internal.MaintenanceJobs;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import com.fasterxml.jackson.databind.JsonNode;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;

/**
 * Vectispire answering the lines it measures, through the real routes (decision 0032, amendment "the
 * scans answer the lines they measure"): a scan completed through the agents' own route and a coverage
 * report accepted through the imports' route — each after its commit, through the ports the owners
 * declare — and the opening of a checklist, each answering a draft's measured lines as Vectispire, marked
 * as such on the screen, in the history, the audit trail and the document; never over a person's answer.
 */
@DisplayName("Vectispire's own answers to measured lines, through the routes")
class ChecklistAutomaticAnswersRoutesTest extends ApiTestBase {

    private static final String TEMPLATES = "/api/v1/checklist-templates";

    /** Line 1: no secret found — passes on a scan whose secrets step produced nothing. */
    private static final Map<String, Object> SECRETS = Map.of("kind", "findings_threshold", "maxAgeDays", 7,
            "scopes", List.of("builtin:secret"), "thresholds", Map.of("critical", Map.of("maxOpen", 0),
                    "high", Map.of("maxOpen", 0)));

    /** Line 2: no infrastructure finding of any severity — fails as soon as an IaC check reports one. */
    private static final Map<String, Object> IAC = Map.of("kind", "findings_threshold", "maxAgeDays", 7,
            "scopes", List.of("builtin:iac"), "thresholds", Map.of("critical", Map.of("maxOpen", 0),
                    "high", Map.of("maxOpen", 0), "medium", Map.of("maxOpen", 0), "low", Map.of("maxOpen", 0),
                    "unknown", Map.of("maxOpen", 0)));

    /** Line 3: 80 % of the lines covered — no data until a coverage report arrives. */
    private static final Map<String, Object> COVERAGE = Map.of("kind", "coverage_threshold", "maxAgeDays", 7,
            "metric", "line", "minimumRatio", 0.8, "aggregation", "per_repository");

    /** A static analysis line: no critical finding of Semgrep's rules — judged only where they read the tree. */
    private static final Map<String, Object> SAST = Map.of("kind", "findings_threshold", "maxAgeDays", 7,
            "scopes", List.of("builtin:sast"), "thresholds", Map.of("critical", Map.of("maxOpen", 0)));

    /** A line on a package: ledger-core present, at 3.2.1 only — judged on the SBOM of the newest scan. */
    private static final Map<String, Object> COMPONENTS = Map.of("kind", "component_versions", "maxAgeDays", 7,
            "components", List.of(Map.of("purlPrefix", "pkg:maven/com.example/ledger-core", "versions",
                    List.of("3.2.1"))));

    /** A clean scan whose SBOM lists ledger-core at {@code version}, as Syft writes it — its purl without one when unknown. */
    private static String sbomOf(String version) {
        String purl = "pkg:maven/com.example/ledger-core" + ("UNKNOWN".equals(version) ? "" : "@" + version);
        return """
                {"secrets":[], "dependencies":[], "duration":"PT1S",
                 "sbom":{"artifacts":[{"name":"ledger-core","version":"%s","purl":"%s","type":"java-archive"}]}}
                """.formatted(version, purl);
    }

    private static final String CLEAN = """
            {"secrets":[], "iac":[], "duration":"PT1S"}
            """;

    private static final String IAC_FINDING = """
            {"secrets":[],
             "iac":[{"checkId":"CKV_AWS_20","checkName":"S3 not public","file":"main.tf","line":4}],
             "duration":"PT1S"}
            """;

    private static final String TWO_IAC_FINDINGS = """
            {"secrets":[],
             "iac":[{"checkId":"CKV_AWS_20","checkName":"S3 not public","file":"main.tf","line":4},
                    {"checkId":"CKV_AWS_21","checkName":"S3 versioned","file":"main.tf","line":9}],
             "duration":"PT1S"}
            """;

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
    private ChecklistAnswerRepository answers;

    @Autowired
    private ProjectChecklistService service;

    @Autowired
    private MaintenanceJobs jobs;

    @Autowired
    private com.asmolabs.vectispire.core.outbox.persistence.OutboxMessageRepository outbox;

    private record Account(String token, long id, String name) {}

    private Account developer;
    private long project;
    private long repository;
    private String agent;

    @BeforeEach
    void estate() throws Exception {
        settings.set(Setting.FOUR_EYES_APPROVAL_REQUIRED, "false");
        developer = account(Role.USER, null);
        project = project("Checkout");
        repository = repository();
        file(project, repository);
        agent = agent();
    }

    // ------------------------------------------------------------------ a scan completes

    @Nested
    @DisplayName("when a scan completes")
    class WhenAScanCompletes {

        @Test
        @DisplayName("a pass is answered yes and a fail no with the measurement as its comment; no data is left unanswered")
        void passFailAndNoData() throws Exception {
            publish("release", List.of(SECRETS, IAC, COVERAGE), false);
            open(developer, "release", null);
            assertThat(answers.findAll()).as("nothing measured yet, nothing answered").isEmpty();
            int before = edition(1);

            completeScan(IAC_FINDING);

            JsonNode view = read(developer, 1);
            JsonNode yes = view.at("/lines/0/answer");
            assertThat(yes.at("/value").asText()).isEqualTo("yes");
            assertThat(yes.at("/answeredBy").asText()).isEqualTo("Vectispire");
            assertThat(yes.at("/answeredByKind").asText()).isEqualTo("system");
            assertThat(yes.at("/measurementId").isNull()).as("rests on the measurement that produced it").isFalse();
            assertThat(yes.at("/withdrawn").asBoolean()).isFalse();

            JsonNode no = view.at("/lines/1/answer");
            assertThat(no.at("/value").asText()).isEqualTo("no");
            assertThat(no.at("/answeredByKind").asText()).isEqualTo("system");
            assertThat(no.at("/comment").asText()).startsWith("Measured by Vectispire (findings_threshold): Fail,");
            assertThat(view.at("/lines/1/problems").isEmpty()).as("the comment a no requires is there").isTrue();

            assertThat(view.at("/lines/2/answer").isNull()).as("no data answers nothing").isTrue();
            assertThat(view.at("/checklist/edition").asInt()).as("one act, one edition").isEqualTo(before + 1);
            assertThat(view.at("/authors")).extracting(JsonNode::asText).as("the system is nobody's name here")
                    .containsExactly(developer.name());

            List<AuditLogEntity> answered = entries("CHECKLIST_ANSWERED");
            assertThat(answered).hasSize(2).allSatisfy(entry -> {
                assertThat(entry.getUserId()).as("nobody asked: no actor, never an invented user").isNull();
                assertThat(entry.getDescription()).contains("automatically by Vectispire");
            });

            JsonNode history = history(1, itemIds(view).get(1));
            assertThat(history.at("/answers")).hasSize(1);
            assertThat(history.at("/answers/0/answeredByKind").asText()).isEqualTo("system");
        }

        @Test
        @DisplayName("run again on the same evidence, the act writes nothing")
        void idempotent() throws Exception {
            publish("release", List.of(SECRETS, IAC, COVERAGE), false);
            open(developer, "release", null);
            completeScan(CLEAN);
            int edition = edition(1);
            long rows = answers.count();
            long audited = entries("CHECKLIST_ANSWERED").size();

            assertThat(service.answerFromEvidence(repository)).isZero();
            assertThat(service.answerFromEvidence(repository)).isZero();

            assertThat(answers.count()).isEqualTo(rows);
            assertThat(edition(1)).as("the edition does not move under the people filling it").isEqualTo(edition);
            assertThat(entries("CHECKLIST_ANSWERED")).hasSize((int) audited);
        }

        @Test
        @DisplayName("a new scan measuring the same thing writes nothing: same value, same figures, same edition")
        void aNewScanMeasuringTheSame() throws Exception {
            publish("release", List.of(SECRETS, IAC, COVERAGE), false);
            open(developer, "release", null);
            completeScan(IAC_FINDING);
            int edition = edition(1);
            long rows = answers.count();
            long audited = entries("CHECKLIST_ANSWERED").size();

            // Another scan, another id and date — another evidence digest — finding the same.
            completeScan(IAC_FINDING);

            assertThat(answers.count()).isEqualTo(rows);
            assertThat(edition(1)).as("no 409 waiting for a person mid-edit").isEqualTo(edition);
            assertThat(entries("CHECKLIST_ANSWERED")).hasSize((int) audited);
        }

        @Test
        @DisplayName("changed figures replace the no with a new one, its comment carrying the new count")
        void changedFiguresReplaceTheComment() throws Exception {
            publish("release", List.of(SECRETS, IAC, COVERAGE), false);
            open(developer, "release", null);
            completeScan(IAC_FINDING);
            long iacLine = itemIds(read(developer, 1)).get(1);
            String before = read(developer, 1).at("/lines/1/answer/comment").asText();
            int edition = edition(1);

            completeScan(TWO_IAC_FINDINGS);

            JsonNode now = read(developer, 1);
            assertThat(now.at("/lines/1/answer/value").asText()).isEqualTo("no");
            assertThat(now.at("/lines/1/answer/comment").asText()).isNotEqualTo(before).contains("2 open");
            assertThat(now.at("/checklist/edition").asInt()).isEqualTo(edition + 1);
            assertThat(history(1, iacLine).at("/answers")).hasSize(2);
            assertThat(now.at("/lines/0/answer/value").asText()).as("the yes states the same, and stays one row")
                    .isEqualTo("yes");
            assertThat(history(1, itemIds(now).get(0)).at("/answers")).hasSize(1);
        }

        @Test
        @DisplayName("a changed measurement replaces Vectispire's answer, and no data withdraws it; the history keeps each")
        void aChangedMeasurementReplacesItsOwnAnswer() throws Exception {
            publish("release", List.of(SECRETS, IAC, COVERAGE), false);
            open(developer, "release", null);
            completeScan(CLEAN);
            long iacLine = itemIds(read(developer, 1)).get(1);
            assertThat(read(developer, 1).at("/lines/1/answer/value").asText()).isEqualTo("yes");

            completeScan(IAC_FINDING);
            JsonNode now = read(developer, 1).at("/lines/1/answer");
            assertThat(now.at("/value").asText()).isEqualTo("no");
            assertThat(now.at("/answeredByKind").asText()).isEqualTo("system");

            // Every scan older than the rule's age: no data, and the "no" resting on the old scans withdrawn.
            scans.findAll().forEach(scan -> {
                scan.setCreatedAt(Instant.now().minus(Duration.ofDays(30)));
                scans.save(scan);
            });
            assertThat(service.answerFromEvidence(repository)).isEqualTo(2);
            JsonNode stale = read(developer, 1);
            assertThat(stale.at("/lines/1/answer").isNull()).as("withdrawn: no current answer").isTrue();
            assertThat(stale.at("/lines/0/answer").isNull()).isTrue();

            JsonNode history = history(1, iacLine).at("/answers");
            assertThat(history).hasSize(3);
            assertThat(history).extracting(row -> row.at("/value").asText()).containsExactly("yes", "no", "no");
            assertThat(history).extracting(row -> row.at("/withdrawn").asBoolean()).containsExactly(false, false, true);
            assertThat(history.get(2).at("/answeredByKind").asText()).isEqualTo("system");

            assertThat(service.answerFromEvidence(repository)).as("withdrawn once, then nothing").isZero();

            // The document reads the line as the screen does: no answer in the workbook, the withdrawal in its history.
            byte[] zip = mvc.perform(authenticated(get(base() + "/1/document"), developer.token()))
                    .andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray();
            JsonNode line = json.readTree(unzip(zip).get("checklist.json")).at("/lines/1");
            assertThat(line.at("/answer").isNull()).as("a withdrawn answer is no answer").isTrue();
            assertThat(line.at("/history/2/withdrawn").asBoolean()).isTrue();
        }

        @Test
        @DisplayName("a static analysis yes is withdrawn once the tree holds a source language its rules do not read")
        void aLanguageNobodyReadWithdrawsTheYes() throws Exception {
            // A false pass here is an automatic "yes, static analysis" in a signed document, on code nobody read.
            settings.set(Setting.SAST_ENABLED, "true");
            publish("release", List.of(SECRETS, SAST), false);
            open(developer, "release", null);

            // A Python tree, and the bundled rule reads Python: examined, nothing found, answered yes.
            completeScan("""
                    {"secrets":[], "sast":[], "languages":["python","yaml"], "duration":"PT1S"}
                    """);
            assertThat(scans.findAll()).extracting(ScanEntity::getSastLanguages)
                    .as("recorded by the dispatcher from the rules the task carried").containsExactly("python");
            long sastLine = itemIds(read(developer, 1)).get(1);
            assertThat(read(developer, 1).at("/lines/1/answer/value").asText()).isEqualTo("yes");

            // Java arrives beside it, and no rule of the task reads Java: no data, and Vectispire's yes withdrawn.
            completeScan("""
                    {"secrets":[], "sast":[], "languages":["java","python","yaml"], "duration":"PT1S"}
                    """);
            JsonNode measurement = read(mvc.perform(authenticated(get(base() + "/1/measurements"), developer.token()))
                    .andExpect(status().isOk())).at("/lines/1/measurement");
            assertThat(measurement.at("/outcome").asText()).isEqualTo("no_data");
            assertThat(measurement.at("/reason").asText()).isEqualTo("language_not_analysed");
            assertThat(measurement.at("/evidence/summary").asText()).contains("not analysed: java");
            assertThat(read(developer, 1).at("/lines/1/answer").isNull()).as("withdrawn: no current answer").isTrue();
            assertThat(read(developer, 1).at("/lines/0/answer/value").asText()).as("the secrets line stands")
                    .isEqualTo("yes");
            JsonNode history = history(1, sastLine).at("/answers");
            assertThat(history).extracting(row -> row.at("/withdrawn").asBoolean()).containsExactly(false, true);
        }

        @Test
        @DisplayName("a no resting on a package's version is withdrawn once the SBOM no longer states that version")
        void anUnstatedVersionWithdrawsTheNo() throws Exception {
            // cpt-boncommande: the version inherited from a parent BOM Syft does not resolve, written UNKNOWN.
            // Read as a version, the line failed and Vectispire answered "no" for a module that is present.
            publish("release", List.of(SECRETS, COMPONENTS), false);
            open(developer, "release", null);
            completeScan(sbomOf("2.0.0"));
            long componentLine = itemIds(read(developer, 1)).get(1);
            assertThat(read(developer, 1).at("/lines/1/answer/value").asText()).as("a stated disallowed version")
                    .isEqualTo("no");

            completeScan(sbomOf("UNKNOWN"));
            JsonNode measurement = read(mvc.perform(authenticated(get(base() + "/1/measurements"), developer.token()))
                    .andExpect(status().isOk())).at("/lines/1/measurement");
            assertThat(measurement.at("/outcome").asText()).isEqualTo("no_data");
            assertThat(measurement.at("/reason").asText()).isEqualTo("version_unrecorded");
            assertThat(measurement.at("/evidence/summary").asText())
                    .contains("pkg:maven/com.example/ledger-core is in its SBOM with no version stated");
            assertThat(read(developer, 1).at("/lines/1/answer").isNull()).as("withdrawn: no current answer").isTrue();
            JsonNode history = history(1, componentLine).at("/answers");
            assertThat(history).extracting(row -> row.at("/withdrawn").asBoolean()).containsExactly(false, true);
        }

        @Test
        @DisplayName("a person's answer is never replaced, and a person answering over Vectispire takes the line over")
        void peopleFirst() throws Exception {
            publish("release", List.of(SECRETS, IAC, COVERAGE), false);
            open(developer, "release", null);
            List<Long> lines = itemIds(read(developer, 1));
            answer(developer, lines.get(0), "no", "The secrets scanner is not trusted yet.", edition(1))
                    .andExpect(status().isCreated());

            completeScan(CLEAN);
            JsonNode view = read(developer, 1);
            assertThat(view.at("/lines/0/answer/value").asText()).as("the person's no stands on a pass").isEqualTo("no");
            assertThat(view.at("/lines/0/answer/answeredByKind").asText()).isEqualTo("person");
            assertThat(view.at("/lines/1/answer/answeredByKind").asText()).isEqualTo("system");

            // The developer answers the line Vectispire answered: theirs from now on.
            answer(developer, lines.get(1), "yes", null, edition(1)).andExpect(status().isCreated());
            completeScan(IAC_FINDING);
            JsonNode after = read(developer, 1);
            assertThat(after.at("/lines/1/answer/answeredBy").asText()).isEqualTo(developer.name());
            assertThat(after.at("/lines/1/answer/answeredByKind").asText()).isEqualTo("person");
            assertThat(after.at("/lines/1/problems")).extracting(JsonNode::asText)
                    .as("the scans leave it, and the submission will name the contradiction")
                    .contains("measurement_contradicted");
            assertThat(after.at("/lines/0/answer/answeredByKind").asText()).isEqualTo("person");
        }

        @Test
        @DisplayName("an account named Vectispire is a person: its answers stand, and it is not the system's author")
        void aUserNamedVectispire() throws Exception {
            publish("release", List.of(SECRETS, IAC, COVERAGE), false);
            Account namesake = account(Role.USER, "Vectispire");
            open(developer, "release", null);
            long line = itemIds(read(developer, 1)).getFirst();
            answer(namesake, line, "no", "Rotated keys are still in history.", edition(1)).andExpect(status().isCreated());

            completeScan(CLEAN);

            JsonNode answer = read(developer, 1).at("/lines/0/answer");
            assertThat(answer.at("/answeredBy").asText()).isEqualTo("Vectispire");
            assertThat(answer.at("/answeredByKind").asText()).as("the same name, a person's answer").isEqualTo("person");
            assertThat(answer.at("/value").asText()).as("never replaced by the scans").isEqualTo("no");
            assertThat(answers.findAll()).filteredOn(row -> row.getItemId() == line).singleElement()
                    .extracting(ChecklistAnswerEntity::getAnsweredById).isEqualTo(namesake.id());
        }

        @Test
        @DisplayName("with the setting off, neither a scan nor an opening writes anything")
        void theSettingOff() throws Exception {
            settings.set(Setting.CHECKLIST_AUTO_ANSWER, "false");
            publish("release", List.of(SECRETS, IAC, COVERAGE), false);
            scan(Instant.now().minusSeconds(60), "secret,iac");
            open(developer, "release", null);
            completeScan(CLEAN);

            assertThat(answers.findAll()).isEmpty();
            assertThat(entries("CHECKLIST_ANSWERED")).isEmpty();
            assertThat(read(developer, 1).at("/checklist/edition").asInt()).isEqualTo(1);
            assertThat(outbox.findAll())
                    .as("nothing queued either: a message whose delivery would do nothing is one to learn to ignore")
                    .noneMatch(message -> com.asmolabs.vectispire.core.checklists.internal.ChecklistAnswerDelivery.TYPE
                            .equals(message.getMessageType()));
        }

        @Test
        @DisplayName("a submitted revision is left as submitted, and Vectispire's answers passed its submission")
        void aSubmittedRevision() throws Exception {
            publish("release", List.of(SECRETS, IAC, COVERAGE), false);
            open(developer, "release", null);
            completeScan(IAC_FINDING);
            long coverageLine = itemIds(read(developer, 1)).get(2);
            answer(developer, coverageLine, "no", "No coverage report yet.", edition(1)).andExpect(status().isCreated());
            // The automatic yes and the automatic no, with its generated comment, meet the submission's rules.
            submit(developer, edition(1)).andExpect(status().isOk());
            int submitted = edition(1);
            long rows = answers.count();

            completeScan(CLEAN);

            assertThat(answers.count()).isEqualTo(rows);
            JsonNode view = read(developer, 1);
            assertThat(view.at("/checklist/status").asText()).isEqualTo("submitted");
            assertThat(view.at("/checklist/edition").asInt()).isEqualTo(submitted);
            assertThat(view.at("/lines/1/answer/value").asText()).isEqualTo("no");
        }

        @Test
        @DisplayName("an automatic yes on a line asking for a file still needs the file before it is submitted")
        void anAutomaticYesStillNeedsItsProof() throws Exception {
            publish("release", List.of(SECRETS), true);
            open(developer, "release", null);
            completeScan(CLEAN);

            JsonNode view = read(developer, 1);
            assertThat(view.at("/lines/0/answer/answeredByKind").asText()).isEqualTo("system");
            assertThat(view.at("/lines/0/problems")).extracting(JsonNode::asText).contains("evidence_required");
            assertThat(view.at("/readyToSubmit").asBoolean()).isFalse();
        }

        @Test
        @DisplayName("an accepted coverage report answers the line it measures")
        void aCoverageImport() throws Exception {
            publish("release", List.of(SECRETS, IAC, COVERAGE), false);
            open(developer, "release", null);
            String key = declaredReportKey();

            mvc.perform(post("/api/v1/repositories/" + repository + "/coverage-imports?format=jacoco")
                            .header("Authorization", "Bearer " + key)
                            .contentType(MediaType.APPLICATION_XML)
                            .content(ReportImportRoutesTest.JACOCO.getBytes(StandardCharsets.UTF_8)))
                    .andExpect(status().isCreated());
            relay();

            JsonNode coverage = read(developer, 1).at("/lines/2/answer");
            assertThat(coverage.at("/value").asText()).isEqualTo("yes");
            assertThat(coverage.at("/answeredByKind").asText()).isEqualTo("system");
        }
    }

    // ------------------------------------------------------------------ opening and moving

    @Test
    @DisplayName("opening a checklist, and moving it to another version, answer at once: the response shows them")
    void openingAndMoving() throws Exception {
        publish("release", List.of(SECRETS, IAC, COVERAGE), false);
        publish("gate", List.of(SECRETS), false);
        scan(Instant.now().minusSeconds(60), "secret,iac");

        JsonNode opened = read(open(developer, "release", null).andExpect(status().isCreated()));
        assertThat(opened.at("/lines/0/answer/answeredByKind").asText()).isEqualTo("system");
        assertThat(opened.at("/lines/1/answer/value").asText()).isEqualTo("yes");
        assertThat(opened.at("/checklist/edition").asInt()).isEqualTo(2);

        JsonNode moved = read(open(developer, "gate", opened.at("/checklist/edition").asInt())
                .andExpect(status().isCreated()));
        assertThat(moved.at("/checklist/revision").asInt()).isEqualTo(2);
        assertThat(moved.at("/lines/0/answer/answeredByKind").asText()).isEqualTo("system");
        assertThat(moved.at("/lines/0/answer/value").asText()).isEqualTo("yes");
    }

    @Test
    @DisplayName("an automatic answer carried onto a new version is written again once, resting on this revision's measurement")
    void aCarriedAutomaticAnswer() throws Exception {
        publish("release", List.of(SECRETS, IAC, COVERAGE), false);
        scan(Instant.now().minusSeconds(60), "secret,iac");
        int edition = read(open(developer, "release", null)).at("/checklist/edition").asInt();
        JsonNode derived = read(mvc.perform(authenticated(post(TEMPLATES + "/release/versions/1/derive"), asAdmin()))
                .andExpect(status().isCreated()));
        mvc.perform(authenticated(post(TEMPLATES + "/release/versions/2/publish"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"revision\":" + derived.at("/version/revision").asInt() + "}"))
                .andExpect(status().isOk());

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("template", "release");
        body.put("version", 2);
        body.put("edition", edition);
        JsonNode moved = read(send(developer, base(), body).andExpect(status().isCreated()));

        JsonNode answer = moved.at("/lines/0/answer");
        assertThat(answer.at("/answeredByKind").asText()).isEqualTo("system");
        assertThat(answer.at("/carriedFromId").isNull()).as("written again, not the carried copy").isTrue();
        assertThat(answer.at("/measurementId").isNull()).isFalse();
        assertThat(history(2, moved.at("/lines/0/itemId").asLong()).at("/answers")).as("the carried copy, then its own")
                .hasSize(2);
        assertThat(service.answerFromEvidence(repository)).as("and then nothing").isZero();
    }

    // ------------------------------------------------------------------ the setting

    @Test
    @DisplayName("the setting is a rule: on by default, the governor's to change, audited — a CISO is refused")
    void theSettingIsTheGovernors() throws Exception {
        JsonNode catalog = read(mvc.perform(authenticated(get("/api/v1/settings"), asAdmin())).andExpect(status().isOk()));
        JsonNode entry = null;
        for (JsonNode section : catalog.findValues("settings")) {
            for (JsonNode setting : section) {
                if (setting.path("key").asText().equals("checklist_auto_answer")) {
                    entry = setting;
                }
            }
        }
        assertThat(entry).as("in the catalog").isNotNull();
        assertThat(entry.path("value").asText()).isEqualTo("true");
        assertThat(entry.path("governor_only").asBoolean()).isTrue();

        mvc.perform(authenticated(put("/api/v1/settings"), asCiso()).contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("checklist_auto_answer", "false"))))
                .andExpect(status().isForbidden());
        assertThat(settings.isEnabled(Setting.CHECKLIST_AUTO_ANSWER)).isTrue();

        mvc.perform(authenticated(put("/api/v1/settings"), tokenFor("governor-" + System.nanoTime(), Role.SUPERUSER, false))
                        .contentType(MediaType.APPLICATION_JSON).content(write(Map.of("checklist_auto_answer", "false"))))
                .andExpect(status().isOk());
        assertThat(settings.isEnabled(Setting.CHECKLIST_AUTO_ANSWER)).isFalse();
        assertThat(entries("SETTING_UPDATED")).anySatisfy(logged ->
                assertThat(logged.getDescription()).contains("checklist_auto_answer"));
    }

    // ------------------------------------------------------------------ the document

    @Test
    @DisplayName("checklist.json names each answer's kind and the Evidence sheet marks the automatic ones")
    void theDocumentMarksThem() throws Exception {
        publish("release", List.of(SECRETS, IAC, COVERAGE), false);
        Account namesake = account(Role.USER, "Vectispire");
        open(developer, "release", null);
        long coverageLine = itemIds(read(developer, 1)).get(2);
        answer(namesake, coverageLine, "no", "No coverage report yet.", edition(1)).andExpect(status().isCreated());
        completeScan(CLEAN);

        byte[] zip = mvc.perform(authenticated(get(base() + "/1/document"), developer.token()))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray();
        Map<String, byte[]> parts = unzip(zip);

        JsonNode statement = json.readTree(parts.get("checklist.json"));
        assertThat(statement.at("/form").asInt()).isEqualTo(2);
        assertThat(statement.at("/lines/0/answer/answeredByKind").asText()).isEqualTo("system");
        assertThat(statement.at("/lines/0/answer/answeredBy").asText()).isEqualTo("Vectispire");
        assertThat(statement.at("/lines/2/answer/answeredByKind").asText()).isEqualTo("person");
        assertThat(statement.at("/lines/2/answer/answeredBy").asText()).isEqualTo("Vectispire");

        Map<String, byte[]> workbook = unzip(parts.get("checklist.xlsx"));
        String evidence = workbook.entrySet().stream()
                .filter(part -> part.getKey().startsWith("xl/worksheets/"))
                .map(part -> new String(part.getValue(), StandardCharsets.UTF_8))
                .filter(xml -> xml.contains("Answered by"))
                .findFirst().orElseThrow();
        assertThat(evidence).contains("Vectispire (automatic, from its measurement)");
        assertThat(count(evidence, "Vectispire (automatic, from its measurement)"))
                .as("the two lines Vectispire answered, not the namesake's").isEqualTo(2);
    }

    // ------------------------------------------------------------------ helpers

    private void completeScan(String result) throws Exception {
        ScanEntity pending = new ScanEntity();
        pending.setRepoId(repository);
        pending.setBranch("main");
        pending.setStatus(ScanStatus.PENDING.wireName());
        pending.setCreatedAt(Instant.now());
        pending.setFindingsCount(0);
        pending.setNewIssuesCount(0);
        pending.setResolvedIssuesCount(0);
        pending.setAttempts(0);
        scans.save(pending);
        MvcResult started = mvc.perform(get("/api/v1/agent/jobs?wait=0").header("Authorization", "Bearer " + agent))
                .andReturn();
        long scanId = json.readTree(mvc.perform(asyncDispatch(started)).andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString()).path("scanId").asLong();
        mvc.perform(post("/api/v1/agent/jobs/" + scanId + "/result")
                        .header("Authorization", "Bearer " + agent)
                        .contentType(MediaType.APPLICATION_JSON).content(result))
                .andExpect(status().isOk());
        assertThat(scans.findById(scanId).orElseThrow().getStatus()).isEqualTo(ScanStatus.COMPLETED.wireName());
        relay();
    }

    /**
     * The relay's pass, as the scheduler runs it every minute: a scan or an import only queues the
     * checklist's answers in its own transaction (decision 0033), and they are given from the outbox.
     */
    private void relay() {
        jobs.relayNotifications();
    }

    /** A completed scan written straight into the table, as one from before: no reaction runs. */
    private void scan(Instant createdAt, String examinedTypes) {
        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repository);
        scan.setBranch("main");
        scan.setStatus(ScanStatus.COMPLETED.wireName());
        scan.setCreatedAt(createdAt);
        scan.setAttempts(1);
        scan.setExaminedTypes(examinedTypes);
        scans.save(scan);
    }

    private String agent() throws Exception {
        JsonNode answer = json.readTree(mvc.perform(authenticated(post("/api/v1/admin/agents"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\": \"agent-" + System.nanoTime() + "\", \"max_concurrent\": 1}"))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
        return answer.get("secret").asText();
    }

    private String declaredReportKey() throws Exception {
        JsonNode key = json.readTree(mvc.perform(authenticated(post("/api/v1/api-keys"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("name", "ci-" + System.nanoTime(), "scopes", List.of("report_import")))))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
        Map<String, Object> source = new LinkedHashMap<>();
        source.put("slug", "ledger-ci");
        source.put("name", "Ledger CI");
        source.put("api_key_id", key.path("key").path("id").asText());
        source.put("project_id", project);
        source.put("kinds", List.of("coverage"));
        mvc.perform(authenticated(post("/api/v1/sarif-sources"), tokenFor("governor-" + System.nanoTime(), Role.SUPERUSER,
                        false)).contentType(MediaType.APPLICATION_JSON).content(write(source)))
                .andExpect(status().isCreated());
        return key.path("secret").asText();
    }

    private String base() {
        return "/api/v1/projects/" + project + "/checklists";
    }

    private Account account(Role role, String name) {
        String username = name != null ? name : role.name().toLowerCase(java.util.Locale.ROOT) + "-" + System.nanoTime();
        String token = tokenFor(username, role, false);
        return new Account(token, users.findByUsername(username).orElseThrow().getId(), username);
    }

    private long project(String name) throws Exception {
        long solution = idOf(mvc.perform(authenticated(post("/api/v1/solutions"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON).content(write(Map.of("name", name + " " + System.nanoTime()))))
                .andExpect(status().isCreated()));
        return idOf(mvc.perform(authenticated(post("/api/v1/solutions/" + solution + "/projects"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON).content(write(Map.of("name", name))))
                .andExpect(status().isCreated()));
    }

    private long repository() {
        RepositoryEntity entity = new RepositoryEntity();
        entity.setUrl("https://example.invalid/checkout-" + System.nanoTime() + ".git");
        entity.setName("checkout");
        entity.setBranch("main");
        return repositories.save(entity).getId();
    }

    private void file(long projectId, long repositoryId) throws Exception {
        mvc.perform(authenticated(put("/api/v1/projects/" + projectId + "/repositories/" + repositoryId), asAdmin()))
                .andExpect(status().isNoContent());
    }

    /**
     * A template of the first workbook's lines under {@code slug}, its first lines bound to {@code rules} in
     * order — each asking for a file when {@code fileRequired} — published by an administrator.
     */
    private void publish(String slug, List<Map<String, Object>> rules, boolean fileRequired) throws Exception {
        List<ChecklistWorkbooks.Line> lines = ChecklistWorkbooks.FIRST;
        mvc.perform(authenticated(post(TEMPLATES + "/" + slug + "/versions"), asAdmin())
                        .contentType(MediaType.APPLICATION_OCTET_STREAM).content(ChecklistWorkbooks.of(lines)))
                .andExpect(status().isCreated());
        JsonNode laid = read(mvc.perform(authenticated(put(TEMPLATES + "/" + slug + "/versions/1/layout"), asAdmin())
                        .param("revision", "1")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(layout(ChecklistWorkbooks.FIRST_ITEM_ROW + lines.size() - 1))))
                .andExpect(status().isOk()));
        int revision = laid.at("/version/revision").asInt();
        List<Map<String, Object>> bindings = new ArrayList<>();
        List<Map<String, Object>> proofs = new ArrayList<>();
        for (int i = 0; i < rules.size(); i++) {
            String itemKey = laid.at("/items/" + i + "/itemKey").asText();
            bindings.add(Map.of("itemKey", itemKey, "rule", rules.get(i)));
            proofs.add(Map.of("itemKey", itemKey, "evidenceKind", "file"));
        }
        if (fileRequired) {
            revision = read(mvc.perform(authenticated(put(TEMPLATES + "/" + slug + "/versions/1/evidence"), asAdmin())
                            .param("revision", String.valueOf(revision))
                            .contentType(MediaType.APPLICATION_JSON).content(write(Map.of("items", proofs))))
                    .andExpect(status().isOk())).at("/version/revision").asInt();
        }
        JsonNode bound = read(mvc.perform(authenticated(put(TEMPLATES + "/" + slug + "/versions/1/rules"), asAdmin())
                        .param("revision", String.valueOf(revision))
                        .contentType(MediaType.APPLICATION_JSON).content(write(Map.of("items", bindings))))
                .andExpect(status().isOk()));
        mvc.perform(authenticated(post(TEMPLATES + "/" + slug + "/versions/1/publish"), asAdmin())
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

    private ResultActions open(Account who, String slug, Integer edition) throws Exception {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("template", slug);
        body.put("version", 1);
        body.put("edition", edition);
        return send(who, base(), body).andExpect(status().isCreated());
    }

    private ResultActions answer(Account who, long item, String value, String comment, int edition) throws Exception {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("value", value);
        body.put("comment", comment);
        body.put("edition", edition);
        return send(who, base() + "/1/items/" + item + "/answers", body);
    }

    private ResultActions submit(Account who, int edition) throws Exception {
        return send(who, base() + "/1/submission", Map.of("edition", edition));
    }

    private ResultActions send(Account who, String path, Map<String, ?> body) throws Exception {
        return mvc.perform(authenticated(post(path), who.token())
                .contentType(MediaType.APPLICATION_JSON).content(write(body)));
    }

    private JsonNode read(Account who, int revision) throws Exception {
        return read(mvc.perform(authenticated(get(base() + "/" + revision), who.token())).andExpect(status().isOk()));
    }

    private JsonNode history(int revision, long item) throws Exception {
        return read(mvc.perform(authenticated(get(base() + "/" + revision + "/items/" + item + "/history"),
                developer.token())).andExpect(status().isOk()));
    }

    private int edition(int revision) throws Exception {
        return read(developer, revision).at("/checklist/edition").asInt();
    }

    private static List<Long> itemIds(JsonNode view) {
        List<Long> ids = new ArrayList<>();
        view.at("/lines").forEach(line -> ids.add(line.at("/itemId").asLong()));
        return ids;
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

    private static Map<String, byte[]> unzip(byte[] zip) throws Exception {
        Map<String, byte[]> parts = new LinkedHashMap<>();
        try (ZipInputStream in = new ZipInputStream(new ByteArrayInputStream(zip))) {
            for (ZipEntry entry = in.getNextEntry(); entry != null; entry = in.getNextEntry()) {
                parts.put(entry.getName(), in.readAllBytes());
            }
        }
        return parts;
    }

    private static int count(String text, String needle) {
        int count = 0;
        for (int at = text.indexOf(needle); at >= 0; at = text.indexOf(needle, at + needle.length())) {
            count++;
        }
        return count;
    }
}
