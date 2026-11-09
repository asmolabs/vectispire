package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.issues.IssueSyncService;
import com.asmolabs.vectispire.core.issues.SlaBreachSignals;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import com.asmolabs.vectispire.core.outbox.persistence.OutboxMessageEntity;
import com.asmolabs.vectispire.core.outbox.persistence.OutboxMessageRepository;
import com.asmolabs.vectispire.core.scanning.ObservedFindings;
import com.asmolabs.vectispire.core.scanning.persistence.FindingEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.maintenance.internal.MaintenanceJobs;
import com.asmolabs.vectispire.core.siem.SiemDelivery;
import com.asmolabs.vectispire.core.siem.SiemEvents;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * The two events the backlog raises — a new secret, a passed remediation deadline — queued in the
 * real outbox, against the real schema, with the SIEM export configured through its route.
 *
 * <p>The default windows apply: critical 15 days, high 30. "Crossed yesterday" is a critical first
 * seen sixteen days ago.
 */
@DisplayName("the SIEM events the backlog raises")
class SiemBacklogSignalsTest extends ApiTestBase {

    @Autowired
    private SlaBreachSignals breaches;

    @Autowired
    private IssueSyncService sync;

    @Autowired
    private IssueRepository issues;

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private OutboxMessageRepository outbox;

    @Autowired
    private SettingsService settings;

    @Autowired
    private TransactionTemplate transactions;

    @Autowired
    private ScanRepository scans;

    @Autowired
    private MaintenanceJobs jobs;

    @Autowired
    private SiemDelivery delivery;

    private Long repoId;

    @BeforeEach
    void exportEverything() throws Exception {
        RepositoryEntity repo = new RepositoryEntity();
        repo.setName("signals");
        repo.setUrl("https://github.com/asmolabs/signals.git");
        repo.setBranch("main");
        repoId = repositories.save(repo).getId();
        export(true);
        outbox.deleteAll();
    }

    @AfterEach
    void publicOnly() {
        settings.set(Setting.SIEM_ALLOW_PRIVATE_DESTINATION, "false");
    }

    @Test
    @DisplayName("a deadline passed within the week is announced once; older, not yet, settled or resolved, never")
    void slaBreachesAreAnnouncedOncePerIssue() {
        Instant now = Instant.now();
        IssueEntity crossed = issue("crossed", "critical", now.minus(Duration.ofDays(16)), TriageStatus.UNDER_REVIEW.wireName());
        // A status this version does not write still counts as undecided: `not in` the settled ones.
        IssueEntity unknownStatus = issue("unknown", "critical", now.minus(Duration.ofDays(16)), "untriaged");
        issue("long-late", "critical", now.minus(Duration.ofDays(30)), TriageStatus.UNDER_REVIEW.wireName());
        issue("on-time", "high", now.minus(Duration.ofDays(10)), TriageStatus.UNDER_REVIEW.wireName());
        issue("settled", "critical", now.minus(Duration.ofDays(16)), TriageStatus.NOT_AFFECTED.wireName());
        IssueEntity resolved = issue("resolved", "critical", now.minus(Duration.ofDays(16)), TriageStatus.UNDER_REVIEW.wireName());
        resolved.resolveAt(now);
        issues.save(resolved);

        assertThat(breaches.signalCrossings()).isEqualTo(2);

        List<OutboxMessageEntity> queued = siemRows();
        assertThat(queued).hasSize(2).allSatisfy(row -> assertThat(row.getPayload())
                .contains("\"eventType\":\"SLA_BREACHED\"")
                .contains("15-day remediation deadline")
                .contains("repository " + repoId));
        assertThat(queued).anySatisfy(row -> assertThat(row.getPayload()).contains("issue " + crossed.getId() + " "));
        assertThat(queued).anySatisfy(row -> assertThat(row.getPayload()).contains("issue " + unknownStatus.getId() + " "));

        // The next turn finds them marked.
        assertThat(breaches.signalCrossings()).isZero();
        assertThat(siemRows()).hasSize(2);
    }

    @Test
    @DisplayName("under the factory minimum a critical or high issue's breach reaches the collector at the issue's severity; a medium or low one's is not queued")
    void aCriticalBreachReachesTheSocUnderTheDefaults() throws Exception {
        try (DatagramSocket collector = new DatagramSocket(0, InetAddress.getLoopbackAddress())) {
            exportWithTheDefaultMinimum("127.0.0.1:" + collector.getLocalPort());
            outbox.deleteAll();
            Instant now = Instant.now();
            IssueEntity critical = issue("critical", "critical", now.minus(Duration.ofDays(16)), TriageStatus.UNDER_REVIEW.wireName());
            IssueEntity high = issue("high", "high", now.minus(Duration.ofDays(31)), TriageStatus.UNDER_REVIEW.wireName());
            issue("medium", "medium", now.minus(Duration.ofDays(91)), TriageStatus.UNDER_REVIEW.wireName());
            issue("low", "low", now.minus(Duration.ofDays(181)), TriageStatus.UNDER_REVIEW.wireName());

            // All four are marked; only the two the minimum admits are queued.
            assertThat(breaches.signalCrossings()).isEqualTo(4);
            assertThat(siemRows()).hasSize(2);

            jobs.relayNotifications();

            List<String> received = receive(collector, 3_000);
            // CEF 8 is syslog 3 (error): 80 + 3. CEF 7 is syslog 3 too; the header field tells them apart.
            assertThat(received).hasSize(2)
                    .anySatisfy(message -> assertThat(message).startsWith("<83>1 ")
                            .contains("|VECTI-SEC-030|Remediation deadline passed|8|")
                            .contains("issue " + critical.getId() + " "))
                    .anySatisfy(message -> assertThat(message)
                            .contains("|VECTI-SEC-030|Remediation deadline passed|7|")
                            .contains("issue " + high.getId() + " "));
        }
    }

    @Test
    @DisplayName("a breach queued before its severity was stored leaves at the type's, 6")
    void aBreachQueuedBeforeTheUpgradeKeepsTheTypesSeverity() throws Exception {
        try (DatagramSocket collector = new DatagramSocket(0, InetAddress.getLoopbackAddress())) {
            exportWithTheDefaultMinimum("127.0.0.1:" + collector.getLocalPort());

            // The payload 0.10.0 wrote: no cefSeverity.
            delivery.deliver(UUID.randomUUID(), """
                    {"eventType":"SLA_BREACHED","timestamp":1790000000000,"message":"queued at 0.10.0","extensions":{}}""");

            assertThat(receive(collector, 3_000)).singleElement().asString()
                    .startsWith("<84>1 ")
                    .contains("|VECTI-SEC-030|Remediation deadline passed|6|")
                    .contains("msg=queued at 0.10.0");
        }
    }

    @Test
    @DisplayName("with the export off a crossing is marked and not queued: switching it on does not replay the week")
    void anExportSwitchedOffDoesNotReplay() throws Exception {
        export(false);
        outbox.deleteAll();
        issue("crossed", "critical", Instant.now().minus(Duration.ofDays(16)), TriageStatus.UNDER_REVIEW.wireName());

        assertThat(breaches.signalCrossings()).isEqualTo(1);
        assertThat(siemRows()).isEmpty();

        export(true);
        outbox.deleteAll();
        assertThat(breaches.signalCrossings()).isZero();
        assertThat(siemRows()).isEmpty();
    }

    @Test
    @DisplayName("a new secret found by a scan is queued in the scan's transaction, once")
    void aNewSecretIsQueuedWithTheScan() {
        FindingEntity leak = new FindingEntity();
        leak.setType(FindingType.SECRET.wireName());
        leak.setIdentifier("aws-access-token");
        leak.setSource("gitleaks");
        leak.setSeverity("high");
        leak.setFilePath("deploy/prod.env");
        leak.setDescription("the matched value never travels");
        leak.setCreatedAt(Instant.now());
        ScanTarget target = new ScanTarget.Repository(repoId);

        for (int round = 0; round < 2; round++) {
            long scanId = scan();
            transactions.executeWithoutResult(status -> sync.sync(scanId, target, ObservedFindings.of(List.of(leak)),
                    Set.of(FindingType.SECRET), Map.of(), null));
        }

        assertThat(siemRows()).singleElement().satisfies(row -> assertThat(row.getPayload())
                .contains("\"eventType\":\"SECRET_LEAK_DETECTED\"")
                .contains("deploy/prod.env")
                .doesNotContain("matched value"));
    }

    private long scan() {
        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repoId);
        scan.setBranch("main");
        scan.setStatus(ScanStatus.COMPLETED.wireName());
        scan.setCreatedAt(Instant.now());
        scan.setFindingsCount(1);
        scan.setNewIssuesCount(0);
        scan.setResolvedIssuesCount(0);
        scan.setAttempts(1);
        return scans.save(scan).getId();
    }

    private IssueEntity issue(String fingerprint, String severity, Instant firstSeen, String triage) {
        IssueEntity issue = new IssueEntity();
        issue.setFingerprint("fp-" + fingerprint);
        issue.setIdentifier("CVE-2026-" + Math.abs(fingerprint.hashCode() % 10_000));
        issue.setType("vulnerability");
        issue.setSeverity(severity);
        issue.setState("open");
        issue.setTriageStatus(triage);
        issue.setPackageName("openssl");
        issue.setRepoId(repoId);
        issue.setFirstSeenAt(firstSeen);
        issue.setLastSeenAt(Instant.now());
        return issues.save(issue);
    }

    private void export(boolean enabled) throws Exception {
        settings.set(Setting.SIEM_ALLOW_PRIVATE_DESTINATION, "true");
        mvc.perform(authenticated(put("/api/v1/siem/config"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"enabled": %s, "protocol": "SYSLOG_UDP", "endpoint": "127.0.0.1:9", "minSeverity": "LOW"}"""
                                .formatted(enabled)))
                .andExpect(status().isOk());
    }

    /** No {@code minSeverity}: the service stores {@code HIGH}, the factory minimum. */
    private void exportWithTheDefaultMinimum(String endpoint) throws Exception {
        settings.set(Setting.SIEM_ALLOW_PRIVATE_DESTINATION, "true");
        mvc.perform(authenticated(put("/api/v1/siem/config"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"enabled": true, "protocol": "SYSLOG_UDP", "endpoint": "%s"}""".formatted(endpoint)))
                .andExpect(status().isOk());
    }

    private static List<String> receive(DatagramSocket collector, int waitMillis) throws Exception {
        List<String> messages = new ArrayList<>();
        collector.setSoTimeout(waitMillis);
        while (true) {
            DatagramPacket packet = new DatagramPacket(new byte[65_536], 65_536);
            try {
                collector.receive(packet);
            } catch (SocketTimeoutException drained) {
                return messages;
            }
            messages.add(new String(packet.getData(), 0, packet.getLength(), StandardCharsets.UTF_8));
            collector.setSoTimeout(300);
        }
    }

    private List<OutboxMessageEntity> siemRows() {
        return outbox.findAll().stream().filter(row -> SiemEvents.TYPE.equals(row.getMessageType())).toList();
    }
}
