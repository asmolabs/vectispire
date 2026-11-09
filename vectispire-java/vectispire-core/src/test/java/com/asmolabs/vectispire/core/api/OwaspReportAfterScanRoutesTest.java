package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.asyncDispatch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogEntity;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogRepository;
import com.asmolabs.vectispire.core.compliance.internal.OwaspReportDelivery;
import com.asmolabs.vectispire.core.compliance.persistence.AiReviewResultEntity;
import com.asmolabs.vectispire.core.compliance.persistence.AiReviewResultRepository;
import com.asmolabs.vectispire.core.maintenance.internal.MaintenanceJobs;
import com.asmolabs.vectispire.core.outbox.persistence.OutboxMessageRepository;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.targets.persistence.ContainerEntity;
import com.asmolabs.vectispire.core.targets.persistence.ContainerRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import com.fasterxml.jackson.databind.JsonNode;
import com.sun.net.httpserver.HttpServer;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;

/**
 * The OWASP report written after a scan, asserted where the wiring lives: a scan completed through the
 * agents' own route, the port {@code scanning} calls in the scan's transaction, the outbox the relay drains
 * on the maintenance tick, the writer's thread, and a model answering over HTTP — a fake Ollama on the
 * loopback, so the request the report sends is read as the model receives it.
 *
 * <p><b>A wiring that is not exercised is not wired</b> (the built-in worker that claimed nothing, the
 * expiry nothing called). Every class of this feature can pass its own tests with the port never
 * implemented, the handler never registered or the setting never read; only a scan completed through the
 * application says a report follows it.
 */
@DisplayName("the OWASP report written after a scan, through the application")
class OwaspReportAfterScanRoutesTest extends ApiTestBase {

    private static final String ANSWER = "## A07 — Identification and Authentication Failures\\n\\nA key is committed.";

    /** A clean scan but for one committed secret — a finding the grid places in A07. */
    private static final String WITH_A_SECRET = """
            {"secrets":[{"rule":"aws-access-token","description":"AWS access key","file":"app.yaml","line":3,
                         "fingerprint":"app.yaml:aws-access-token:3"}],
             "iac":[], "duration":"PT1S"}
            """;

    /** Every step absent and one broken: the target was never examined, and the scan is failed. */
    private static final String NOTHING_EXAMINED = """
            {"failures":[{"step":"clone","reason":"the clone failed"}], "duration":"PT1S"}
            """;

    @Autowired
    private SettingsService settings;

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private ContainerRepository containers;

    @Autowired
    private ScanRepository scans;

    @Autowired
    private AiReviewResultRepository reports;

    @Autowired
    private OutboxMessageRepository outbox;

    @Autowired
    private AuditLogRepository auditLog;

    @Autowired
    private MaintenanceJobs jobs;

    private HttpServer model;
    private final List<String> asked = new CopyOnWriteArrayList<>();
    private long repository;
    private String agent;

    @BeforeEach
    void estate() throws Exception {
        model = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        model.createContext("/api/chat", exchange -> {
            asked.add(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            byte[] body = ("{\"message\":{\"role\":\"assistant\",\"content\":\"" + ANSWER + "\"}}")
                    .getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        model.start();

        settings.set(Setting.AI_REVIEW_ENABLED, "true");
        settings.set(Setting.AI_REVIEW_OLLAMA_URL, "http://127.0.0.1:" + model.getAddress().getPort());
        settings.set(Setting.AI_REVIEW_OWASP_AFTER_SCAN, "true");
        repository = repository();
        agent = agent();
    }

    @AfterEach
    void stopTheModel() {
        model.stop(0);
    }

    @Test
    @DisplayName("a repository's completed scan, with the setting on, leaves a report built from that scan")
    void aCompletedScanLeavesAReport() throws Exception {
        long scanId = complete(repositoryScan(), WITH_A_SECRET, ScanStatus.COMPLETED);

        AiReviewResultEntity report = settled();
        assertThat(report.getStatus()).isEqualTo("completed");
        assertThat(report.getScanId()).isEqualTo(scanId);
        assertThat(report.getRepoId()).isEqualTo(repository);
        assertThat(report.getResponse()).contains("A07");

        // What the model was sent carries the grid's placement and the repository's grid, not a
        // category the model would choose.
        assertThat(asked).hasSize(1);
        assertThat(asked.getFirst()).contains("secret | A07 | ");
        assertThat(asked.getFirst()).contains("OWASP coverage of this repository");
        assertThat(asked.getFirst()).contains("Never move a finding to another category");

        // Audited like the button's run, with nobody named: nobody asked.
        AuditLogEntity entry = audited();
        assertThat(entry.getResourceId()).isEqualTo(String.valueOf(repository));
        assertThat(entry.getDescription()).contains("after scan " + scanId);
        assertThat(entry.getUserId()).isNull();

        // Read through the route, as any reader reaches it.
        JsonNode read = json.readTree(mvc.perform(authenticated(get("/api/v1/repositories/" + repository + "/owasp-review"),
                        asAdmin()))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
        assertThat(read.path("scanId").asLong()).isEqualTo(scanId);
        assertThat(read.path("status").asText()).isEqualTo("completed");
    }

    @Test
    @DisplayName("with the setting off, a completed scan asks for nothing")
    void offAsksForNothing() throws Exception {
        settings.set(Setting.AI_REVIEW_OWASP_AFTER_SCAN, "false");

        complete(repositoryScan(), WITH_A_SECRET, ScanStatus.COMPLETED);

        assertNothingAsked();
    }

    @Test
    @DisplayName("with model review off, the setting alone asks for nothing")
    void modelReviewOffAsksForNothing() throws Exception {
        settings.set(Setting.AI_REVIEW_ENABLED, "false");

        complete(repositoryScan(), WITH_A_SECRET, ScanStatus.COMPLETED);

        assertNothingAsked();
    }

    @Test
    @DisplayName("a failed scan asks for nothing")
    void aFailedScanAsksForNothing() throws Exception {
        complete(repositoryScan(), NOTHING_EXAMINED, ScanStatus.FAILED);

        assertNothingAsked();
    }

    @Test
    @DisplayName("an image's completed scan asks for nothing: the Top 10 is about an application")
    void anImageScanAsksForNothing() throws Exception {
        complete(imageScan(), WITH_A_SECRET, ScanStatus.COMPLETED);

        assertNothingAsked();
    }

    /**
     * Nothing queued — the deterministic half: a message never written cannot be delivered later — and,
     * after the relay's pass, no report and no call to the model.
     */
    private void assertNothingAsked() {
        assertThat(outbox.findAll()).noneMatch(message -> OwaspReportDelivery.TYPE.equals(message.getMessageType()));
        assertThat(reports.findAll()).isEmpty();
        assertThat(asked).isEmpty();
    }

    /** The report, once the writer's thread has settled it — polled, since it is written beside the request. */
    private AiReviewResultEntity settled() throws InterruptedException {
        Instant until = Instant.now().plus(Duration.ofSeconds(30));
        while (Instant.now().isBefore(until)) {
            List<AiReviewResultEntity> rows = reports.findAll();
            if (rows.size() == 1 && !"running".equals(rows.getFirst().getStatus())) {
                return rows.getFirst();
            }
            Thread.sleep(100);
        }
        throw new AssertionError("No settled OWASP report within 30 seconds: " + reports.findAll().size() + " row(s)");
    }

    /**
     * The audit entry, written after the row is settled — waited for too, so it is not written into the
     * next test's emptied table.
     */
    private AuditLogEntity audited() throws InterruptedException {
        Instant until = Instant.now().plus(Duration.ofSeconds(30));
        while (Instant.now().isBefore(until)) {
            List<AuditLogEntity> entries = auditLog.findAll().stream()
                    .filter(entry -> "AI_REVIEW_REQUESTED".equals(entry.getOperationType()))
                    .toList();
            if (!entries.isEmpty()) {
                assertThat(entries).hasSize(1);
                return entries.getFirst();
            }
            Thread.sleep(100);
        }
        throw new AssertionError("No audit entry for the OWASP report within 30 seconds");
    }

    /** Claims the pending scan as the agent, posts its result, and runs the relay's pass. */
    private long complete(long pending, String result, ScanStatus expected) throws Exception {
        MvcResult started = mvc.perform(get("/api/v1/agent/jobs?wait=0").header("Authorization", "Bearer " + agent))
                .andReturn();
        long scanId = json.readTree(mvc.perform(asyncDispatch(started)).andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString()).path("scanId").asLong();
        assertThat(scanId).isEqualTo(pending);
        mvc.perform(post("/api/v1/agent/jobs/" + scanId + "/result")
                        .header("Authorization", "Bearer " + agent)
                        .contentType(MediaType.APPLICATION_JSON).content(result))
                .andExpect(status().isOk());
        assertThat(scans.findById(scanId).orElseThrow().getStatus()).isEqualTo(expected.wireName());
        jobs.relayNotifications();
        return scanId;
    }

    private long repositoryScan() {
        ScanEntity scan = pendingScan();
        scan.setRepoId(repository);
        scan.setBranch("main");
        return scans.save(scan).getId();
    }

    private long imageScan() {
        ContainerEntity image = new ContainerEntity();
        image.setImageName("team/service-" + System.nanoTime());
        image.setTag("1.0");
        ScanEntity scan = pendingScan();
        scan.setContainerId(containers.save(image).getId());
        scan.setBranch("");
        return scans.save(scan).getId();
    }

    private static ScanEntity pendingScan() {
        ScanEntity scan = new ScanEntity();
        scan.setStatus(ScanStatus.PENDING.wireName());
        scan.setCreatedAt(Instant.now());
        scan.setFindingsCount(0);
        scan.setNewIssuesCount(0);
        scan.setResolvedIssuesCount(0);
        scan.setAttempts(0);
        return scan;
    }

    private long repository() {
        RepositoryEntity entity = new RepositoryEntity();
        entity.setUrl("https://example.invalid/checkout-" + System.nanoTime() + ".git");
        entity.setName("checkout");
        entity.setBranch("main");
        return repositories.save(entity).getId();
    }

    private String agent() throws Exception {
        JsonNode answer = json.readTree(mvc.perform(authenticated(post("/api/v1/admin/agents"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("name", "agent-" + System.nanoTime(), "max_concurrent", 1))))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
        return answer.get("secret").asText();
    }
}
