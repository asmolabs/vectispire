package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.access.VisibilityMode;
import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.crypto.Digests;
import com.asmolabs.vectispire.common.domain.reportplugins.ReportPluginManifest;
import com.asmolabs.vectispire.common.domain.reportplugins.ReportRunReason;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.common.scanning.scanners.ReportPluginRenderer;
import com.asmolabs.vectispire.core.access.persistence.UserRepository;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogEntity;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogRepository;
import com.asmolabs.vectispire.core.outbox.persistence.OutboxMessageRepository;
import com.asmolabs.vectispire.core.reportplugins.ReportExecutor;
import com.asmolabs.vectispire.core.reportplugins.internal.ReportExecution;
import com.asmolabs.vectispire.core.reportplugins.internal.ReportExportRetentionTask;
import com.asmolabs.vectispire.core.reportplugins.internal.ReportQueue;
import com.asmolabs.vectispire.core.reportplugins.internal.ReportWorker;
import com.asmolabs.vectispire.core.reportplugins.persistence.ReportExportRepository;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.siem.SiemEvents;
import com.fasterxml.jackson.databind.JsonNode;
import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.ResultActions;

/**
 * Report runs (decision 0035 §2, lot R3) through the real routes, filter chain, queue and database: who may ask
 * for a report of which project, what is refused before anything is queued, what the claim settles again, the
 * states a run ends in and what each leaves in the audit log, the SIEM and the tables.
 *
 * <p><b>The container is the one part stood in for</b> — {@link ReportExecutor}, whose real implementation the
 * container suite runs end to end ({@code ReportPluginRendererIntegrationTest}). Everything around it is real:
 * the export the stand-in receives is the one the service built for the requester, and the queue is driven by
 * {@link ReportWorker#drain}, the worker's own claim and execution on the test's thread.
 */
@DisplayName("report runs, through the routes")
class ReportRunsRoutesTest extends ApiTestBase {

    static final String IMAGE = "registry.example.internal/reports/summary@sha256:" + "a".repeat(64);
    static final String OTHER_IMAGE = "registry.example.internal/reports/summary@sha256:" + "b".repeat(64);
    static final String PROJECT_NOT_FOUND = "Project not found.";
    static final byte[] DOCUMENT = "summary, rendered".getBytes(StandardCharsets.UTF_8);

    @MockitoBean
    private ReportExecutor executor;

    @Autowired
    private SettingsService settings;

    @Autowired
    private AuditLogRepository auditLog;

    @Autowired
    private OutboxMessageRepository outbox;

    @Autowired
    private UserRepository users;

    @Autowired
    private ReportExportRepository exports;

    @Autowired
    private ReportWorker worker;

    @Autowired
    private ReportQueue queue;

    @Autowired
    private ReportExecution execution;

    @Autowired
    private ReportExportRetentionTask retention;

    @Autowired
    private JdbcTemplate jdbc;

    private String governor;
    private long project;

    /** What the stand-in was handed, the last time it was called. */
    private final AtomicReference<byte[]> handed = new AtomicReference<>();

    @BeforeEach
    void estate() throws Exception {
        reset(executor);
        handed.set(null);
        when(executor.render(any(), any())).thenAnswer(call -> {
            handed.set(call.getArgument(1));
            return new ReportPluginRenderer.Outcome.Produced(DOCUMENT);
        });
        settings.set(Setting.FOUR_EYES_APPROVAL_REQUIRED, "false");
        governor = tokenFor("governor-" + System.nanoTime(), Role.SUPERUSER, false);
        long solution = idOf(mvc.perform(authenticated(post("/api/v1/solutions"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON).content(write(Map.of("name", "Payments " + System.nanoTime()))))
                .andExpect(status().isCreated()));
        project = idOf(mvc.perform(authenticated(post("/api/v1/solutions/" + solution + "/projects"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON).content(write(Map.of("name", "Checkout"))))
                .andExpect(status().isCreated()));
        mvc.perform(authenticated(post("/api/v1/report-plugins"), governor)
                .contentType(MediaType.APPLICATION_JSON).content(write(ReportPluginsRoutesTest.manifest(IMAGE))))
                .andExpect(status().isCreated());
        activate(project).andExpect(status().isOk());
    }

    private ResultActions activate(long projectId) throws Exception {
        return mvc.perform(authenticated(put("/api/v1/projects/" + projectId + "/report-plugins/summary"), asCiso()));
    }

    private ResultActions request(String token, long projectId, String pluginId) throws Exception {
        return mvc.perform(authenticated(post("/api/v1/projects/" + projectId + "/reports"), token)
                .header("Accept-Language", "fr-BE,fr;q=0.9")
                .contentType(MediaType.APPLICATION_JSON).content(write(Map.of("pluginId", pluginId))));
    }

    private ResultActions request(String token) throws Exception {
        return request(token, project, "summary");
    }

    private JsonNode body(ResultActions result) throws Exception {
        return json.readTree(result.andReturn().getResponse().getContentAsString());
    }

    private long idOf(ResultActions result) throws Exception {
        return body(result).path("id").asLong();
    }

    private JsonNode run(long runId) throws Exception {
        return body(mvc.perform(authenticated(get("/api/v1/projects/" + project + "/reports/" + runId), asAdmin()))
                .andExpect(status().isOk()));
    }

    private List<AuditLogEntity> entries(AuditOperation operation) {
        return auditLog.findAll().stream().filter(entry -> operation.wireName().equals(entry.getOperationType())).toList();
    }

    private static void assertConflict(ResultActions result, String cause) throws Exception {
        result.andExpect(status().isConflict()).andExpect(jsonPath("$.type").value("urn:vectispire:problem:" + cause));
    }

    @Nested
    @DisplayName("requesting")
    class Requesting {

        @Test
        @DisplayName("write accounts and auditors who see the whole project; the governor is refused, after the project")
        void who() throws Exception {
            JsonNode queued = body(request(asReader()).andExpect(status().isAccepted()));
            assertThat(queued.at("/state").asText()).isEqualTo("pending");
            assertThat(queued.at("/pluginId").asText()).isEqualTo("summary");
            assertThat(queued.at("/projectName").asText()).isEqualTo("Checkout");
            assertThat(queued.at("/manifestDigest").isNull()).as("the digest is the claim's").isTrue();
            assertThat(entries(AuditOperation.REPORT_REQUESTED)).singleElement()
                    .satisfies(entry -> assertThat(entry.getDescription()).contains("summary").contains("Checkout"));
            worker.drain();

            request(asAuditor()).andExpect(status().isAccepted());
            worker.drain();
            request(asCiso()).andExpect(status().isAccepted());
            worker.drain();

            request(governor).andExpect(status().isForbidden());
            assertThat(detailOf(request(governor, project + 100_000, "summary").andExpect(status().isNotFound())
                    .andReturn())).isEqualTo(PROJECT_NOT_FOUND);
            assertThat(entries(AuditOperation.REPORT_REQUESTED)).hasSize(3);
        }

        @Test
        @DisplayName("an integration key asks for no report, whatever its scope: the export is built for a person")
        void noIntegrationKey() throws Exception {
            String exporter = json.readTree(mvc.perform(authenticated(post("/api/v1/api-keys"), asAdmin())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(write(Map.of("name", "exporter", "scopes", List.of("export")))))
                    .andExpect(status().isOk()).andReturn().getResponse().getContentAsString()).path("secret").asText();

            request(exporter).andExpect(status().isForbidden());
            assertThat(entries(AuditOperation.REPORT_REQUESTED)).isEmpty();
        }

        @Test
        @DisplayName("a project not seen whole is absent, in the words of one that does not exist")
        void hiddenProject() throws Exception {
            settings.set(Setting.TARGET_VISIBILITY, VisibilityMode.ASSIGNED.wireName());

            assertThat(detailOf(request(asReader()).andExpect(status().isNotFound()).andReturn()))
                    .isEqualTo(PROJECT_NOT_FOUND);
            assertThat(detailOf(request(asReader(), project + 100_000, "summary").andExpect(status().isNotFound())
                    .andReturn())).isEqualTo(PROJECT_NOT_FOUND);
            assertThat(detailOf(mvc.perform(authenticated(get("/api/v1/projects/" + project + "/reports"), asReader()))
                    .andExpect(status().isNotFound()).andReturn())).isEqualTo(PROJECT_NOT_FOUND);
            assertThat(entries(AuditOperation.REPORT_REQUESTED)).isEmpty();
        }

        @Test
        @DisplayName("a plugin not switched on here, or not registered, is the same 404; a blank one a 400")
        void notActivated() throws Exception {
            mvc.perform(authenticated(delete("/api/v1/projects/" + project + "/report-plugins/summary"), asCiso()))
                    .andExpect(status().isNoContent());

            String off = detailOf(request(asAdmin()).andExpect(status().isNotFound()).andReturn());
            String unknown = detailOf(request(asAdmin(), project, "nothing").andExpect(status().isNotFound()).andReturn());
            assertThat(off).isEqualTo("Report plugin \"summary\" is not switched on for project " + project + ".");
            assertThat(unknown).isEqualTo("Report plugin \"nothing\" is not switched on for project " + project + ".");
            request(asAdmin(), project, " ").andExpect(status().isBadRequest());
            assertThat(entries(AuditOperation.REPORT_REQUESTED)).isEmpty();
        }

        @Test
        @DisplayName("a disabled plugin, and one whose manifest was withdrawn, are refused before anything is queued")
        void disabledOrWithdrawn() throws Exception {
            mvc.perform(authenticated(put("/api/v1/report-plugins/summary/enabled"), governor)
                    .contentType(MediaType.APPLICATION_JSON).content("{\"enabled\": false}")).andExpect(status().isOk());
            assertConflict(request(asAdmin()), "report-plugin-disabled");
            mvc.perform(authenticated(put("/api/v1/report-plugins/summary/enabled"), governor)
                    .contentType(MediaType.APPLICATION_JSON).content("{\"enabled\": true}")).andExpect(status().isOk());

            withdraw(approvedDigest());
            assertConflict(request(asAdmin()), "report-plugin-not-approved");
            assertThat(entries(AuditOperation.REPORT_REQUESTED)).isEmpty();
        }

        @Test
        @DisplayName("an unapproved manifest never runs: pending under four-eyes, the approved one is what is asked")
        void notApproved() throws Exception {
            settings.set(Setting.FOUR_EYES_APPROVAL_REQUIRED, "true");
            mvc.perform(authenticated(put("/api/v1/report-plugins/summary"), governor)
                            .contentType(MediaType.APPLICATION_JSON).content(write(ReportPluginsRoutesTest.manifest(OTHER_IMAGE))))
                    .andExpect(status().isOk());
            String approved = approvedDigest();

            long runId = idOf(request(asAdmin()).andExpect(status().isAccepted()));
            worker.drain();

            ArgumentCaptor<ReportPluginManifest> ran = ArgumentCaptor.forClass(ReportPluginManifest.class);
            verify(executor).render(ran.capture(), any());
            assertThat(ran.getValue().image()).as("the approved image, not the pending one").isEqualTo(IMAGE);
            assertThat(run(runId).at("/manifestDigest").asText()).isEqualTo(approved);
        }

        @Test
        @DisplayName("one run of a plugin per project at a time: the second waits for the first, then may queue")
        void oneAtATime() throws Exception {
            long first = idOf(request(asAdmin()).andExpect(status().isAccepted()));
            assertConflict(request(asAuditor()), "report-run-in-progress");

            // Another project's run of the same plugin is not this one's to wait for.
            long solution = idOf(mvc.perform(authenticated(post("/api/v1/solutions"), asAdmin())
                    .contentType(MediaType.APPLICATION_JSON).content(write(Map.of("name", "Other " + System.nanoTime())))));
            long other = idOf(mvc.perform(authenticated(post("/api/v1/solutions/" + solution + "/projects"), asAdmin())
                    .contentType(MediaType.APPLICATION_JSON).content(write(Map.of("name", "Ledger")))));
            activate(other).andExpect(status().isOk());
            request(asAdmin(), other, "summary").andExpect(status().isAccepted());

            assertThat(worker.drain()).isEqualTo(2);
            assertThat(run(first).at("/state").asText()).isEqualTo("produced");
            request(asAuditor()).andExpect(status().isAccepted());
        }
    }

    @Nested
    @DisplayName("running")
    class Running {

        @Test
        @DisplayName("produced: the requester's export at the claim, kept with the run, every digest recorded and audited")
        void produced() throws Exception {
            long runId = idOf(request(asAdmin()).andExpect(status().isAccepted()));
            assertThat(worker.drain()).isOne();

            byte[] export = handed.get();
            JsonNode document = json.readTree(export);
            assertThat(document.at("/schema").asText()).isEqualTo("vectispire-project-export");
            assertThat(document.at("/project/id").asLong()).isEqualTo(project);
            assertThat(document.at("/export/locale").asText()).isEqualTo("fr-BE");

            JsonNode ended = run(runId);
            assertThat(ended.at("/state").asText()).isEqualTo("produced");
            assertThat(ended.at("/reason").isNull()).isTrue();
            assertThat(ended.at("/manifestDigest").asText()).isEqualTo(approvedDigest());
            assertThat(ended.at("/imageDigest").asText()).isEqualTo("sha256:" + "a".repeat(64));
            assertThat(ended.at("/signerIdentity").asText())
                    .isEqualTo("https://ci.example.internal/reports/summary/release@refs/tags/v1");
            assertThat(ended.at("/signerIssuer").asText()).isEqualTo("https://ci.example.internal/oidc");
            assertThat(ended.at("/exportSchemaVersion").asText()).isEqualTo("1.0");
            assertThat(ended.at("/exportSha256").asText()).isEqualTo(Digests.sha256Hex(export));
            assertThat(ended.at("/exportSize").asLong()).isEqualTo(export.length);
            assertThat(ended.at("/outputSha256").asText()).isEqualTo(Digests.sha256Hex(DOCUMENT));
            assertThat(ended.at("/outputSize").asLong()).isEqualTo(DOCUMENT.length);
            assertThat(ended.at("/exitCode").asInt()).isZero();
            assertThat(ended.at("/productVersion").asText()).isNotBlank();
            assertThat(Instant.parse(ended.at("/startedAt").asText()))
                    .isBeforeOrEqualTo(Instant.parse(ended.at("/exportedAt").asText()));
            assertThat(Instant.parse(ended.at("/exportedAt").asText()))
                    .isBeforeOrEqualTo(Instant.parse(ended.at("/finishedAt").asText()));

            assertThat(exports.findById(runId).orElseThrow().getContent()).as("the input the signature will attest to")
                    .isEqualTo(export);
            assertThat(entries(AuditOperation.PROJECT_EXPORTED)).singleElement()
                    .satisfies(entry -> assertThat(entry.getDescription()).contains(Digests.sha256Hex(export))
                            .contains("report plugin \"summary\""));
            assertThat(entries(AuditOperation.REPORT_PRODUCED)).singleElement()
                    .satisfies(entry -> assertThat(entry.getDescription()).contains(Digests.sha256Hex(DOCUMENT))
                            .contains(approvedDigest()));
            assertThat(body(mvc.perform(authenticated(get("/api/v1/projects/" + project + "/reports"), asAuditor()))
                    .andExpect(status().isOk())).at("/0/id").asLong()).isEqualTo(runId);
        }

        @Test
        @DisplayName("refused: no export kept, none handed over, REPORT_REFUSED signalled as VECTI-SEC-033")
        void refused() throws Exception {
            siem();
            when(executor.render(any(), any())).thenReturn(new ReportPluginRenderer.Outcome.Refused(
                    ReportRunReason.SIGNATURE_UNVERIFIED, "Its image's signature was not verified. cosign: no signatures found"));
            long runId = idOf(request(asAdmin()).andExpect(status().isAccepted()));
            worker.drain();

            JsonNode ended = run(runId);
            assertThat(ended.at("/state").asText()).isEqualTo("refused");
            assertThat(ended.at("/reason").asText()).isEqualTo("signature_unverified");
            assertThat(ended.at("/detail").asText()).contains("no signatures found");
            assertThat(ended.at("/signerIdentity").isNull()).as("no signer was verified").isTrue();
            assertThat(exports.existsById(runId)).isFalse();
            assertThat(entries(AuditOperation.PROJECT_EXPORTED)).isEmpty();
            assertThat(entries(AuditOperation.REPORT_REFUSED)).singleElement()
                    .satisfies(entry -> assertThat(entry.getDescription()).contains("signature_unverified"));
            assertThat(siemEvents()).contains("REPORT_PLUGIN_REFUSED").doesNotContain("PROJECT_EXPORTED");
        }

        @Test
        @DisplayName("failed: nothing kept but the run and its reason; the export it reached is audited, not the failure signalled")
        void failed() throws Exception {
            siem();
            when(executor.render(any(), any())).thenReturn(new ReportPluginRenderer.Outcome.Failed(
                    ReportRunReason.EXIT_CODE, "It exited with 3. template missing", true));
            long runId = idOf(request(asAdmin()).andExpect(status().isAccepted()));
            worker.drain();

            JsonNode ended = run(runId);
            assertThat(ended.at("/state").asText()).isEqualTo("failed");
            assertThat(ended.at("/reason").asText()).isEqualTo("exit_code");
            assertThat(ended.at("/outputSha256").isNull()).isTrue();
            assertThat(exports.existsById(runId)).isFalse();
            assertThat(entries(AuditOperation.PROJECT_EXPORTED)).hasSize(1);
            assertThat(entries(AuditOperation.REPORT_FAILED)).singleElement()
                    .satisfies(entry -> assertThat(entry.getDescription()).contains("exit_code"));
            assertThat(siemEvents()).contains("PROJECT_EXPORTED").doesNotContain("REPORT_PLUGIN_REFUSED");
            request(asAdmin()).andExpect(status().isAccepted());
        }

        @Test
        @DisplayName("switched off, or withdrawn, between the request and the claim: failed, and nothing runs")
        void pluginGoneAtTheClaim() throws Exception {
            long switchedOff = idOf(request(asAdmin()).andExpect(status().isAccepted()));
            mvc.perform(authenticated(delete("/api/v1/projects/" + project + "/report-plugins/summary"), asCiso()))
                    .andExpect(status().isNoContent());
            worker.drain();
            assertThat(run(switchedOff).at("/reason").asText()).isEqualTo("plugin_unavailable");

            activate(project).andExpect(status().isOk());
            long withdrawn = idOf(request(asAdmin()).andExpect(status().isAccepted()));
            withdraw(approvedDigest());
            worker.drain();
            assertThat(run(withdrawn).at("/state").asText()).isEqualTo("failed");
            assertThat(run(withdrawn).at("/reason").asText()).isEqualTo("plugin_unavailable");

            verify(executor, never()).render(any(), any());
            assertThat(entries(AuditOperation.PROJECT_EXPORTED)).isEmpty();
            assertThat(entries(AuditOperation.REPORT_FAILED)).hasSize(2);
        }

        @Test
        @DisplayName("a requester who no longer sees the whole project, or is deactivated, gets no export built")
        void requesterAtTheClaim() throws Exception {
            String username = "writer-" + System.nanoTime();
            String writer = tokenFor(username, Role.USER, false);
            long narrowed = idOf(request(writer).andExpect(status().isAccepted()));
            settings.set(Setting.TARGET_VISIBILITY, VisibilityMode.ASSIGNED.wireName());
            worker.drain();
            assertThat(run(narrowed).at("/reason").asText()).isEqualTo("requester_not_allowed");

            settings.set(Setting.TARGET_VISIBILITY, VisibilityMode.EVERYONE.wireName());
            long deactivated = idOf(request(writer).andExpect(status().isAccepted()));
            var account = users.findByUsername(username).orElseThrow();
            account.setIsActive(false);
            users.save(account);
            worker.drain();
            assertThat(run(deactivated).at("/reason").asText()).isEqualTo("requester_not_allowed");

            verify(executor, never()).render(any(), any());
            assertThat(entries(AuditOperation.PROJECT_EXPORTED)).isEmpty();
        }
    }

    @Nested
    @DisplayName("the lease")
    class Lease {

        @Test
        @DisplayName("a run whose executor stopped answering is failed as lost, and its executor writes nothing after")
        void lapsed() throws Exception {
            long runId = idOf(request(asAdmin()).andExpect(status().isAccepted()));
            assertThat(queue.claim("dead-instance")).contains(runId);

            // Within its lease the run is another executor's: the turn neither fails it nor takes it again.
            worker.drain();
            assertThat(run(runId).at("/state").asText()).isEqualTo("running");
            verify(executor, never()).render(any(), any());

            // A day back: the driver may read the timestamp in the JVM's zone, and an hour's offset must not
            // leave the lease still running.
            jdbc.update("update t_report_run set lease_expires_at = ? where id = ?",
                    Timestamp.from(Instant.now().minusSeconds(86_400)), runId);
            worker.drain();
            JsonNode lost = run(runId);
            assertThat(lost.at("/state").asText()).isEqualTo("failed");
            assertThat(lost.at("/reason").asText()).isEqualTo("executor_lost");
            assertThat(entries(AuditOperation.REPORT_FAILED)).singleElement()
                    .satisfies(entry -> assertThat(entry.getDescription()).contains("executor_lost"));

            // The dead instance comes back and carries the run out: nothing it learns is recorded.
            execution.execute(runId, "dead-instance");
            assertThat(run(runId).at("/reason").asText()).isEqualTo("executor_lost");
            assertThat(exports.existsById(runId)).isFalse();
            assertThat(entries(AuditOperation.REPORT_PRODUCED)).isEmpty();

            request(asAdmin()).andExpect(status().isAccepted());
        }
    }

    @Nested
    @DisplayName("keeping")
    class Keeping {

        @Test
        @DisplayName("the evidence window takes an export's bytes, never the run nor its digest")
        void retention() throws Exception {
            long runId = idOf(request(asAdmin()).andExpect(status().isAccepted()));
            worker.drain();
            String digest = run(runId).at("/exportSha256").asText();

            retention.run();
            assertThat(exports.existsById(runId)).as("inside the window").isTrue();

            jdbc.update("update t_report_export set created_at = ? where run_id = ?",
                    Timestamp.from(Instant.now().minusSeconds(401L * 86_400)), runId);
            retention.run();
            assertThat(exports.existsById(runId)).isFalse();
            assertThat(run(runId).at("/exportSha256").asText()).isEqualTo(digest);
        }

        @Test
        @DisplayName("deleting the project takes its runs and their exports, in the same transaction")
        void projectDeleted() throws Exception {
            long runId = idOf(request(asAdmin()).andExpect(status().isAccepted()));
            worker.drain();
            mvc.perform(authenticated(delete("/api/v1/projects/" + project), asAdmin())).andExpect(status().isNoContent());
            assertThat(jdbc.queryForObject("select count(*) from t_report_run where project_id = ?", Long.class, project))
                    .isZero();
            assertThat(exports.existsById(runId)).isFalse();
        }

        @Test
        @DisplayName("a run is read through its own project only")
        void readThroughItsProject() throws Exception {
            long runId = idOf(request(asAdmin()).andExpect(status().isAccepted()));
            long solution = idOf(mvc.perform(authenticated(post("/api/v1/solutions"), asAdmin())
                    .contentType(MediaType.APPLICATION_JSON).content(write(Map.of("name", "Other " + System.nanoTime())))));
            long other = idOf(mvc.perform(authenticated(post("/api/v1/solutions/" + solution + "/projects"), asAdmin())
                    .contentType(MediaType.APPLICATION_JSON).content(write(Map.of("name", "Ledger")))));
            assertThat(detailOf(mvc.perform(authenticated(get("/api/v1/projects/" + other + "/reports/" + runId), asAdmin()))
                    .andExpect(status().isNotFound()).andReturn())).isEqualTo("Report run " + runId + " not found.");
        }
    }

    private String approvedDigest() throws Exception {
        return body(mvc.perform(authenticated(get("/api/v1/report-plugins/summary"), governor)).andExpect(status().isOk()))
                .at("/approvedDigest").asText();
    }

    private void withdraw(String digest) throws Exception {
        mvc.perform(authenticated(post("/api/v1/report-plugins/summary/manifests/" + digest + "/withdrawal"), governor)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("justification", "The renderer dropped accepted issues from the sheet."))))
                .andExpect(status().isOk());
    }

    private void siem() throws Exception {
        settings.set(Setting.SIEM_ALLOW_PRIVATE_DESTINATION, "true");
        mvc.perform(authenticated(put("/api/v1/siem/config"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"enabled": true, "protocol": "SYSLOG_UDP", "endpoint": "127.0.0.1:9", "minSeverity": "LOW"}"""))
                .andExpect(status().isOk());
        outbox.deleteAll();
    }

    /** The SIEM event types queued in the outbox. */
    private List<String> siemEvents() {
        return outbox.findAll().stream()
                .filter(row -> SiemEvents.TYPE.equals(row.getMessageType()))
                .map(row -> {
                    try {
                        return json.readTree(row.getPayload()).get("eventType").asText();
                    } catch (Exception unreadable) {
                        throw new IllegalStateException(unreadable);
                    }
                })
                .toList();
    }
}
