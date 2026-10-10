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

import com.asmolabs.vectispire.common.domain.reportplugins.ProjectExportSchema;
import com.asmolabs.vectispire.common.domain.access.VisibilityMode;
import com.asmolabs.vectispire.common.domain.attestation.DsseEnvelope;
import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.checklists.DocumentZip;
import com.asmolabs.vectispire.common.domain.crypto.CosignSigner;
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
import com.asmolabs.vectispire.core.reportplugins.internal.ReportEvidenceRetentionTask;
import com.asmolabs.vectispire.core.reportplugins.internal.ReportQueue;
import com.asmolabs.vectispire.core.reportplugins.internal.ReportWorker;
import com.asmolabs.vectispire.core.reportplugins.persistence.ReportDocumentRepository;
import com.asmolabs.vectispire.core.reportplugins.persistence.ReportExportRepository;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.siem.SiemEvents;
import com.fasterxml.jackson.databind.JsonNode;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
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
    /** A one-sheet workbook: what the manifest declares, so that it passes the check. */
    static final byte[] DOCUMENT = workbook(false);

    /** The same workbook carrying a VBA project: a macro-enabled package under the declared {@code .xlsx}. */
    static final byte[] DISGUISED = workbook(true);

    static byte[] workbook(boolean withMacro) {
        String relationships = "http://schemas.openxmlformats.org/package/2006/relationships";
        LinkedHashMap<String, DocumentZip.Entry> parts = new LinkedHashMap<>();
        parts.put("[Content_Types].xml", DocumentZip.Entry.of(("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                + "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">"
                + "<Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>"
                + "<Default Extension=\"xml\" ContentType=\"application/xml\"/>"
                + "<Override PartName=\"/xl/workbook.xml\" ContentType=\"application/vnd.openxmlformats-officedocument."
                + "spreadsheetml.sheet.main+xml\"/></Types>").getBytes(StandardCharsets.UTF_8)));
        parts.put("_rels/.rels", DocumentZip.Entry.of(("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                + "<Relationships xmlns=\"" + relationships + "\"><Relationship Id=\"rId1\" "
                + "Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" "
                + "Target=\"xl/workbook.xml\"/></Relationships>").getBytes(StandardCharsets.UTF_8)));
        parts.put("xl/workbook.xml", DocumentZip.Entry.of(("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                + "<workbook xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\"><sheets/></workbook>")
                .getBytes(StandardCharsets.UTF_8)));
        if (withMacro) {
            parts.put("xl/vbaProject.bin", DocumentZip.Entry.of(new byte[] {(byte) 0xD0, (byte) 0xCF, 0x11, (byte) 0xE0}));
        }
        return DocumentZip.of(parts);
    }

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
    private ReportDocumentRepository documents;

    @Autowired
    private ReportWorker worker;

    @Autowired
    private ReportQueue queue;

    @Autowired
    private ReportExecution execution;

    @Autowired
    private ReportEvidenceRetentionTask retention;

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
            JsonNode accepted = body(request(asAdmin()).andExpect(status().isAccepted()));
            long runId = accepted.at("/id").asLong();
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
            assertThat(ended.at("/exportSchemaVersion").asText()).isEqualTo(ProjectExportSchema.VERSION);
            assertThat(ended.at("/exportSha256").asText()).isEqualTo(Digests.sha256Hex(export));
            assertThat(ended.at("/exportSize").asLong()).isEqualTo(export.length);
            assertThat(ended.at("/outputSha256").asText()).isEqualTo(Digests.sha256Hex(DOCUMENT));
            assertThat(ended.at("/outputSize").asLong()).isEqualTo(DOCUMENT.length);
            assertThat(ended.at("/exitCode").asInt()).isZero();
            assertThat(ended.at("/productVersion").asText()).isNotBlank();
            // What the 202 said is what the row keeps: a nanosecond clock (Linux) against a column of microseconds
            // that MySQL rounds would make them a microsecond apart, and the provenance reads the row.
            assertThat(Instant.parse(accepted.at("/requestedAt").asText()))
                    .isEqualTo(Instant.parse(ended.at("/requestedAt").asText()));
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

    @Nested
    @DisplayName("the document")
    class Documents {

        private ResultActions download(String token, long projectId, long runId) throws Exception {
            return mvc.perform(authenticated(get("/api/v1/projects/" + projectId + "/reports/" + runId + "/document"),
                    token));
        }

        private PublicKey publishedKey() throws Exception {
            return CosignSigner.parsePublicKey(mvc.perform(get("/api/v1/crypto/public-key.pub"))
                    .andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
        }

        @Test
        @DisplayName("produced: the file, never signed raw, and the signed provenance of every recorded field")
        void package_() throws Exception {
            long runId = idOf(request(asAdmin()).andExpect(status().isAccepted()));
            worker.drain();
            JsonNode ended = run(runId);
            assertThat(ended.at("/state").asText()).isEqualTo("produced");

            var response = download(asAuditor(), project, runId).andExpect(status().isOk()).andReturn().getResponse();
            assertThat(response.getContentType()).isEqualTo("application/zip");
            assertThat(response.getHeader("Content-Disposition"))
                    .startsWith("attachment").contains("report-" + runId + "-summary.zip");
            assertThat(response.getHeaders("X-Content-Type-Options")).contains("nosniff");
            assertThat(response.getHeaders("Content-Security-Policy")).contains("sandbox");

            byte[] content = response.getContentAsByteArray();
            Map<String, byte[]> entries = unzip(content);
            // No summary.xlsx.sig: the key signs VEX and CSAF raw, so a raw signature over a plugin's bytes would
            // vouch for a VEX document an image chose to write. The file is bound by the provenance's subject only.
            assertThat(entries.keySet()).containsExactly("summary.xlsx", "provenance.json");
            assertThat(entries.get("summary.xlsx")).as("the plugin's file, byte for byte").isEqualTo(DOCUMENT);

            PublicKey key = publishedKey();
            DsseEnvelope envelope = json.readValue(entries.get("provenance.json"), DsseEnvelope.class);
            assertThat(envelope.payloadType()).isEqualTo("application/vnd.in-toto+json");
            assertThat(CosignSigner.verifyDsse(envelope, key)).as("the provenance's envelope verifies against the published key").isTrue();

            JsonNode statement = json.readTree(Base64.getDecoder().decode(envelope.payload()));
            assertThat(statement.at("/_type").asText()).isEqualTo("https://in-toto.io/Statement/v1");
            assertThat(statement.at("/predicateType").asText()).isEqualTo("https://vectispire.dev/report-provenance/v1");
            assertThat(statement.at("/subject/0/name").asText()).isEqualTo("summary.xlsx");
            assertThat(statement.at("/subject/0/digest/sha256").asText()).isEqualTo(Digests.sha256Hex(DOCUMENT));
            JsonNode predicate = statement.at("/predicate");
            assertThat(predicate.at("/run/id").asLong()).isEqualTo(runId);
            for (String instant : List.of("requestedAt", "startedAt", "exportedAt", "finishedAt")) {
                assertThat(Instant.parse(predicate.at("/run/" + instant).asText())).as(instant)
                        .isEqualTo(Instant.parse(ended.at("/" + instant).asText()));
            }
            assertThat(predicate.at("/project/id").asLong()).isEqualTo(project);
            assertThat(predicate.at("/project/name").asText()).isEqualTo("Checkout");
            assertThat(predicate.at("/requester/accountId").asLong()).isPositive();
            assertThat(predicate.at("/requester").has("displayName")).isTrue();
            assertThat(predicate.at("/plugin/id").asText()).isEqualTo("summary");
            assertThat(predicate.at("/plugin/manifestDigest").asText()).isEqualTo(approvedDigest());
            assertThat(predicate.at("/plugin/image").asText()).isEqualTo(IMAGE);
            assertThat(predicate.at("/plugin/imageDigest").asText()).isEqualTo("sha256:" + "a".repeat(64));
            assertThat(predicate.at("/plugin/signer/identity").asText())
                    .isEqualTo("https://ci.example.internal/reports/summary/release@refs/tags/v1");
            assertThat(predicate.at("/plugin/signer/issuer").asText()).isEqualTo("https://ci.example.internal/oidc");
            assertThat(predicate.at("/export/schema").asText()).isEqualTo("vectispire-project-export");
            assertThat(predicate.at("/export/schemaVersion").asText()).isEqualTo(ProjectExportSchema.VERSION);
            assertThat(predicate.at("/export/sha256").asText()).isEqualTo(ended.at("/exportSha256").asText())
                    .isEqualTo(Digests.sha256Hex(handed.get()));
            assertThat(predicate.at("/export/id").asText()).isEqualTo(json.readTree(handed.get()).at("/export/id").asText());
            assertThat(Instant.parse(predicate.at("/run/exportedAt").asText()))
                    .as("one export, one instant: the provenance's and the export's own generated_at")
                    .isEqualTo(Instant.parse(json.readTree(handed.get()).at("/export/generated_at").asText()));
            assertThat(predicate.at("/output/mediaType").asText())
                    .isEqualTo("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
            assertThat(predicate.at("/output/size").asLong()).isEqualTo(DOCUMENT.length);
            assertThat(predicate.at("/producer/productVersion").asText()).isEqualTo(ended.at("/productVersion").asText());
            assertThat(predicate.at("/producer/signingKeyId").asText()).isEqualTo(CosignSigner.computeKeyId(key))
                    .isEqualTo(ended.at("/signingKeyId").asText());
            assertThat(predicate.at("/claim").asText()).contains("does not claim the document is a true rendering");

            assertThat(ended.at("/packageSha256").asText()).isEqualTo(Digests.sha256Hex(content));
            assertThat(ended.at("/outputMediaType").asText())
                    .isEqualTo("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
            assertThat(entries(AuditOperation.REPORT_PRODUCED)).singleElement()
                    .satisfies(entry -> assertThat(entry.getDescription()).contains(Digests.sha256Hex(content)));
            assertThat(entries(AuditOperation.REPORT_DOWNLOADED)).singleElement()
                    .satisfies(entry -> assertThat(entry.getDescription()).contains(Digests.sha256Hex(content))
                            .contains(Digests.sha256Hex(DOCUMENT)));
        }

        @Test
        @DisplayName("an output that is not what it declares is refused, discarded unsigned, and signalled VECTI-SEC-033")
        void refusedOutput() throws Exception {
            siem();
            when(executor.render(any(), any())).thenReturn(new ReportPluginRenderer.Outcome.Produced(DISGUISED));
            long runId = idOf(request(asAdmin()).andExpect(status().isAccepted()));
            worker.drain();

            JsonNode ended = run(runId);
            assertThat(ended.at("/state").asText()).isEqualTo("refused");
            assertThat(ended.at("/reason").asText()).isEqualTo("output_refused");
            assertThat(ended.at("/detail").asText()).contains("VBA project").contains("discarded");
            assertThat(ended.at("/outputSha256").asText()).as("which file was refused").isEqualTo(Digests.sha256Hex(DISGUISED));
            assertThat(ended.at("/signerIdentity").asText()).as("who vouched for the image that wrote it")
                    .isEqualTo("https://ci.example.internal/reports/summary/release@refs/tags/v1");
            assertThat(ended.at("/packageSha256").isNull()).isTrue();
            assertThat(ended.at("/signingKeyId").isNull()).as("nothing was signed").isTrue();
            assertThat(documents.existsById(runId)).isFalse();
            assertThat(exports.existsById(runId)).isFalse();

            assertThat(entries(AuditOperation.PROJECT_EXPORTED)).as("the export did reach the plugin").hasSize(1);
            assertThat(entries(AuditOperation.REPORT_REFUSED)).singleElement()
                    .satisfies(entry -> assertThat(entry.getDescription()).contains("output_refused")
                            .contains(Digests.sha256Hex(DISGUISED)));
            assertThat(entries(AuditOperation.REPORT_PRODUCED)).isEmpty();
            assertThat(siemEvents()).contains("REPORT_PLUGIN_REFUSED", "PROJECT_EXPORTED");
            assertThat(detailOf(download(asAdmin(), project, runId).andExpect(status().isNotFound()).andReturn()))
                    .isEqualTo("Report run " + runId + " has no document: it is refused, and only a produced run has one.");
        }

        @Test
        @DisplayName("who may read the run may download it; a project not seen whole is absent, in the same words")
        void authorization() throws Exception {
            long runId = idOf(request(asAdmin()).andExpect(status().isAccepted()));
            assertThat(detailOf(download(asAdmin(), project, runId).andExpect(status().isNotFound()).andReturn()))
                    .isEqualTo("Report run " + runId + " has no document: it is pending; its document comes when it "
                            + "produces.");
            worker.drain();

            download(asReader(), project, runId).andExpect(status().isOk());
            settings.set(Setting.TARGET_VISIBILITY, VisibilityMode.ASSIGNED.wireName());
            assertThat(detailOf(download(asReader(), project, runId).andExpect(status().isNotFound()).andReturn()))
                    .isEqualTo(PROJECT_NOT_FOUND);
            assertThat(detailOf(download(asReader(), project + 100_000, runId).andExpect(status().isNotFound())
                    .andReturn())).isEqualTo(PROJECT_NOT_FOUND);
            settings.set(Setting.TARGET_VISIBILITY, VisibilityMode.EVERYONE.wireName());

            long solution = idOf(mvc.perform(authenticated(post("/api/v1/solutions"), asAdmin())
                    .contentType(MediaType.APPLICATION_JSON).content(write(Map.of("name", "Other " + System.nanoTime())))));
            long other = idOf(mvc.perform(authenticated(post("/api/v1/solutions/" + solution + "/projects"), asAdmin())
                    .contentType(MediaType.APPLICATION_JSON).content(write(Map.of("name", "Ledger")))));
            assertThat(detailOf(download(asAdmin(), other, runId).andExpect(status().isNotFound()).andReturn()))
                    .as("a run is downloaded through its own project only")
                    .isEqualTo("Report run " + runId + " not found.");

            String exporter = json.readTree(mvc.perform(authenticated(post("/api/v1/api-keys"), asAdmin())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(write(Map.of("name", "exporter", "scopes", List.of("export")))))
                    .andExpect(status().isOk()).andReturn().getResponse().getContentAsString()).path("secret").asText();
            download(exporter, project, runId).andExpect(status().isForbidden());

            assertThat(entries(AuditOperation.REPORT_DOWNLOADED)).as("only the one download that was served")
                    .hasSize(1);
        }

        @Test
        @DisplayName("the evidence window takes the document's bytes, never the run nor its digests; the download says so")
        void retention() throws Exception {
            long runId = idOf(request(asAdmin()).andExpect(status().isAccepted()));
            worker.drain();
            String packageSha256 = run(runId).at("/packageSha256").asText();

            ReportRunsRoutesTest.this.retention.run();
            assertThat(documents.existsById(runId)).as("inside the window").isTrue();

            jdbc.update("update t_report_document set created_at = ? where run_id = ?",
                    Timestamp.from(Instant.now().minusSeconds(401L * 86_400)), runId);
            ReportRunsRoutesTest.this.retention.run();
            assertThat(documents.existsById(runId)).isFalse();
            assertThat(exports.existsById(runId)).as("the export has its own date").isTrue();
            assertThat(run(runId).at("/packageSha256").asText()).isEqualTo(packageSha256);
            assertThat(detailOf(download(asAdmin(), project, runId).andExpect(status().isNotFound()).andReturn()))
                    .contains("no longer kept").contains(packageSha256);
        }

        @Test
        @DisplayName("deleting the project takes its documents, in the same transaction")
        void projectDeleted() throws Exception {
            long runId = idOf(request(asAdmin()).andExpect(status().isAccepted()));
            worker.drain();
            assertThat(documents.existsById(runId)).isTrue();
            mvc.perform(authenticated(delete("/api/v1/projects/" + project), asAdmin())).andExpect(status().isNoContent());
            assertThat(documents.existsById(runId)).isFalse();
        }

        private Map<String, byte[]> unzip(byte[] content) throws IOException {
            Map<String, byte[]> entries = new LinkedHashMap<>();
            try (ZipInputStream zip = new ZipInputStream(new ByteArrayInputStream(content))) {
                ZipEntry entry;
                while ((entry = zip.getNextEntry()) != null) {
                    entries.put(entry.getName(), zip.readAllBytes());
                }
            }
            return entries;
        }
    }

    @Nested
    @DisplayName("withdrawal, and a document's standing")
    class Withdrawal {

        static final String JUSTIFICATION = "The renderer dropped accepted issues from the sheet.";

        private ResultActions download(String token, long runId) throws Exception {
            return mvc.perform(authenticated(get("/api/v1/projects/" + project + "/reports/" + runId + "/document"),
                    token));
        }

        private ResultActions standingOf(String token, String sha256) throws Exception {
            return mvc.perform(authenticated(get("/api/v1/report-documents/" + sha256), token));
        }

        private long produced() throws Exception {
            long runId = idOf(request(asAdmin()).andExpect(status().isAccepted()));
            worker.drain();
            assertThat(run(runId).at("/state").asText()).isEqualTo("produced");
            return runId;
        }

        /** The answer to a digest nothing produced, for the same caller: what a hidden document must equal. */
        private JsonNode unknownTo(String token, String sha256) throws Exception {
            return body(standingOf(token, sha256).andExpect(status().isOk()));
        }

        @Test
        @DisplayName("withdrawing a digest withdraws every document it produced, and only those; they stay downloadable, flagged")
        void everyDocumentOfTheDigest() throws Exception {
            String first = approvedDigest();
            long one = produced();
            long two = produced();
            // A run of the same digest that produced nothing: no document, none to count.
            when(executor.render(any(), any())).thenReturn(new ReportPluginRenderer.Outcome.Produced(DISGUISED));
            long refused = idOf(request(asAdmin()).andExpect(status().isAccepted()));
            worker.drain();
            when(executor.render(any(), any())).thenReturn(new ReportPluginRenderer.Outcome.Produced(DOCUMENT));

            mvc.perform(authenticated(put("/api/v1/report-plugins/summary"), governor)
                            .contentType(MediaType.APPLICATION_JSON).content(write(ReportPluginsRoutesTest.manifest(OTHER_IMAGE))))
                    .andExpect(status().isOk());
            String second = approvedDigest();
            assertThat(second).isNotEqualTo(first);
            long three = produced();
            assertThat(download(asAdmin(), one).andReturn().getResponse().getHeader("Vectispire-Document-Status"))
                    .as("before the withdrawal").isEqualTo("upheld");

            withdraw(first);

            for (long withdrawn : List.of(one, two)) {
                JsonNode view = run(withdrawn);
                assertThat(Instant.parse(view.at("/withdrawnAt").asText())).isBeforeOrEqualTo(Instant.now());
                assertThat(view.at("/withdrawnBy").asText()).startsWith("governor-");
                assertThat(view.at("/withdrawalJustification").asText()).isEqualTo(JUSTIFICATION);
                var response = download(asAdmin(), withdrawn).andExpect(status().isOk()).andReturn().getResponse();
                assertThat(response.getHeader("Vectispire-Document-Status")).isEqualTo("withdrawn");
                assertThat(Digests.sha256Hex(response.getContentAsByteArray()))
                        .as("the package kept as it was handed out").isEqualTo(view.at("/packageSha256").asText());
                JsonNode standing = body(standingOf(asReader(), view.at("/packageSha256").asText()).andExpect(status().isOk()));
                assertThat(standing.at("/standing").asText()).isEqualTo("withdrawn");
                assertThat(standing.at("/productions/0/withdrawalJustification").asText()).isEqualTo(JUSTIFICATION);
            }
            JsonNode standing = run(three);
            assertThat(standing.at("/withdrawnAt").isNull()).as("another digest's document stands").isTrue();
            assertThat(standing.at("/withdrawalJustification").isNull()).isTrue();
            assertThat(download(asAdmin(), three).andReturn().getResponse().getHeader("Vectispire-Document-Status"))
                    .isEqualTo("upheld");
            assertThat(body(standingOf(asReader(), standing.at("/packageSha256").asText())).at("/standing").asText())
                    .isEqualTo("upheld");
            // The three wrote the same file: the bytes are still vouched for by the digest that stands.
            JsonNode sameFile = body(standingOf(asReader(), Digests.sha256Hex(DOCUMENT)).andExpect(status().isOk()));
            assertThat(sameFile.at("/standing").asText()).isEqualTo("upheld");
            assertThat(sameFile.at("/productions").findValuesAsText("runId")).containsExactly(
                    String.valueOf(three), String.valueOf(two), String.valueOf(one));

            Map<Long, Boolean> listed = new LinkedHashMap<>();
            body(mvc.perform(authenticated(get("/api/v1/projects/" + project + "/reports"), asReader()))
                    .andExpect(status().isOk())).forEach(row -> listed.put(row.at("/id").asLong(),
                            JUSTIFICATION.equals(row.at("/withdrawalJustification").asText(null))));
            assertThat(listed).as("every run of the digest says so, the refused one too; the other digest's does not")
                    .containsExactlyInAnyOrderEntriesOf(Map.of(one, true, two, true, refused, true, three, false));

            assertThat(entries(AuditOperation.REPORT_PLUGIN_WITHDRAWN)).singleElement()
                    .satisfies(entry -> assertThat(entry.getDescription()).contains("2 document(s) withdrawn with it"));
            assertThat(entries(AuditOperation.REPORT_DOWNLOADED))
                    .filteredOn(entry -> entry.getDescription().contains("served as withdrawn")).hasSize(2);
        }

        @Test
        @DisplayName("the status route: known by its package or its file, unknown otherwise, a malformed digest a 400")
        void knownAndUnknown() throws Exception {
            long runId = produced();
            JsonNode ended = run(runId);
            String packageSha256 = ended.at("/packageSha256").asText();

            JsonNode known = body(standingOf(asAuditor(), packageSha256.toUpperCase()).andExpect(status().isOk()));
            assertThat(known.at("/sha256").asText()).isEqualTo(packageSha256);
            assertThat(known.at("/standing").asText()).isEqualTo("upheld");
            assertThat(known.at("/productions")).hasSize(1);
            JsonNode production = known.at("/productions/0");
            assertThat(production.at("/matched").asText()).isEqualTo("package");
            assertThat(production.at("/runId").asLong()).isEqualTo(runId);
            assertThat(production.at("/projectId").asLong()).isEqualTo(project);
            assertThat(production.at("/projectName").asText()).isEqualTo("Checkout");
            assertThat(production.at("/pluginId").asText()).isEqualTo("summary");
            assertThat(production.at("/manifestDigest").asText()).isEqualTo(approvedDigest());
            assertThat(production.at("/imageDigest").asText()).isEqualTo(ended.at("/imageDigest").asText());
            assertThat(production.at("/signingKeyId").asText()).isEqualTo(ended.at("/signingKeyId").asText()).isNotBlank();
            assertThat(Instant.parse(production.at("/producedAt").asText()))
                    .isEqualTo(Instant.parse(ended.at("/finishedAt").asText()));
            assertThat(production.at("/documentKept").asBoolean()).isTrue();
            assertThat(production.at("/withdrawnAt").isNull()).isTrue();

            JsonNode byFile = body(standingOf(asAuditor(), "sha256:" + Digests.sha256Hex(DOCUMENT)).andExpect(status().isOk()));
            assertThat(byFile.at("/standing").asText()).isEqualTo("upheld");
            assertThat(byFile.at("/productions/0/matched").asText()).isEqualTo("output");
            assertThat(byFile.at("/productions/0/runId").asLong()).isEqualTo(runId);

            String nothing = Digests.sha256Hex(("never produced " + System.nanoTime()).getBytes(StandardCharsets.UTF_8));
            JsonNode unknown = unknownTo(asAuditor(), nothing);
            assertThat(unknown.at("/standing").asText()).isEqualTo("unknown");
            assertThat(unknown.at("/productions")).isEmpty();
            assertThat(unknown.at("/sha256").asText()).isEqualTo(nothing);
            // Refused output: its file is named by its run, but nothing this installation signed.
            when(executor.render(any(), any())).thenReturn(new ReportPluginRenderer.Outcome.Produced(DISGUISED));
            request(asAdmin()).andExpect(status().isAccepted());
            worker.drain();
            assertThat(body(standingOf(asAuditor(), Digests.sha256Hex(DISGUISED))).at("/standing").asText())
                    .isEqualTo("unknown");

            for (String malformed : List.of("abc", "z".repeat(64), packageSha256 + "0")) {
                standingOf(asAuditor(), malformed).andExpect(status().isBadRequest());
            }
            mvc.perform(get("/api/v1/report-documents/" + packageSha256)).andExpect(status().isUnauthorized());
            String exporter = json.readTree(mvc.perform(authenticated(post("/api/v1/api-keys"), asAdmin())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(write(Map.of("name", "exporter", "scopes", List.of("export")))))
                    .andExpect(status().isOk()).andReturn().getResponse().getContentAsString()).path("secret").asText();
            standingOf(exporter, packageSha256).andExpect(status().isForbidden());
        }

        @Test
        @DisplayName("a document of a project not seen whole, or deleted, answers exactly as one never produced")
        void hiddenIsUnknown() throws Exception {
            long runId = produced();
            String packageSha256 = run(runId).at("/packageSha256").asText();
            String nothing = Digests.sha256Hex(("never produced " + System.nanoTime()).getBytes(StandardCharsets.UTF_8));
            assertThat(body(standingOf(asReader(), packageSha256)).at("/standing").asText()).isEqualTo("upheld");

            settings.set(Setting.TARGET_VISIBILITY, VisibilityMode.ASSIGNED.wireName());
            String hidden = standingOf(asReader(), packageSha256).andExpect(status().isOk()).andReturn().getResponse()
                    .getContentAsString();
            String absent = standingOf(asReader(), nothing).andExpect(status().isOk()).andReturn().getResponse()
                    .getContentAsString();
            assertThat(hidden).isEqualTo(absent.replace(nothing, packageSha256));
            assertThat(body(standingOf(asAdmin(), packageSha256)).at("/standing").asText())
                    .as("an administrator sees every project").isEqualTo("upheld");
            settings.set(Setting.TARGET_VISIBILITY, VisibilityMode.EVERYONE.wireName());

            withdraw(approvedDigest());
            mvc.perform(authenticated(delete("/api/v1/projects/" + project), asAdmin())).andExpect(status().isNoContent());
            assertThat(standingOf(asAdmin(), packageSha256).andReturn().getResponse().getContentAsString())
                    .isEqualTo(standingOf(asAdmin(), nothing).andReturn().getResponse().getContentAsString()
                            .replace(nothing, packageSha256));
        }

        @Test
        @DisplayName("past the evidence window the document is no longer kept, and its standing is still answered")
        void purgedStillAnswered() throws Exception {
            long runId = produced();
            String packageSha256 = run(runId).at("/packageSha256").asText();
            withdraw(approvedDigest());
            jdbc.update("update t_report_document set created_at = ? where run_id = ?",
                    Timestamp.from(Instant.now().minusSeconds(401L * 86_400)), runId);
            ReportRunsRoutesTest.this.retention.run();

            JsonNode standing = body(standingOf(asReader(), packageSha256).andExpect(status().isOk()));
            assertThat(standing.at("/standing").asText()).isEqualTo("withdrawn");
            assertThat(standing.at("/productions/0/documentKept").asBoolean()).isFalse();
        }

        @Test
        @DisplayName("withdrawn while the run was in hand: nothing is signed, the run fails plugin_unavailable")
        void withdrawnWhileRunning() throws Exception {
            String digest = approvedDigest();
            when(executor.render(any(), any())).thenAnswer(call -> {
                withdraw(digest);
                return new ReportPluginRenderer.Outcome.Produced(DOCUMENT);
            });
            long runId = idOf(request(asAdmin()).andExpect(status().isAccepted()));
            worker.drain();

            JsonNode ended = run(runId);
            assertThat(ended.at("/state").asText()).isEqualTo("failed");
            assertThat(ended.at("/reason").asText()).isEqualTo("plugin_unavailable");
            assertThat(ended.at("/detail").asText()).contains("withdrawn while it ran").contains("nothing was signed");
            assertThat(ended.at("/signingKeyId").isNull()).isTrue();
            assertThat(ended.at("/withdrawalJustification").asText()).isEqualTo(JUSTIFICATION);
            assertThat(documents.existsById(runId)).isFalse();
            assertThat(entries(AuditOperation.REPORT_PRODUCED)).isEmpty();
            assertThat(entries(AuditOperation.REPORT_FAILED)).hasSize(1);
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
