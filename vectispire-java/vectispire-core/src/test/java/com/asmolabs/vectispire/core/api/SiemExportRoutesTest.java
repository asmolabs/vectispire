package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.notifications.OutboxRetry;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.siem.CefEvent;
import com.asmolabs.vectispire.common.domain.siem.SecurityEventType;
import com.asmolabs.vectispire.core.persistence.OutboxMessageEntity;
import com.asmolabs.vectispire.core.repositories.Outbox;
import com.asmolabs.vectispire.core.services.MaintenanceJobs;
import com.asmolabs.vectispire.core.services.SettingsService;
import com.asmolabs.vectispire.core.services.SiemEvents;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.transaction.IllegalTransactionStateException;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * The SIEM export end to end: an audited action, the outbox, the relay, a real socket.
 *
 * <p><b>A wiring that is not exercised is not wired.</b> Every piece below has its own test; what
 * only this suite can see is that they are connected — that the audit log tells the SIEM queue,
 * that the relay knows the SIEM message type, that the scheduled job runs the relay. The relay is
 * driven through {@link MaintenanceJobs#relayNotifications()}, the method the scheduler calls, so
 * a handler that no bean supplies, or a job that stops calling the relay, turns this red.
 *
 * <p>The collectors listen on loopback, reached because the test allows private URLs — the
 * production setting an operator uses for an internal collector — not through a test switch.
 */
@DisplayName("the SIEM export, from an audited action to a collector")
class SiemExportRoutesTest extends ApiTestBase {

    @Autowired
    private MaintenanceJobs jobs;

    @Autowired
    private SiemEvents events;

    @Autowired
    private Outbox outbox;

    @Autowired
    private SettingsService settings;

    @Autowired
    private TransactionTemplate transactions;

    @Test
    @DisplayName("issuing an API key reaches a UDP collector as a CEF event, after the relay runs")
    void anAuditedActionReachesTheCollector() throws Exception {
        try (DatagramSocket collector = new DatagramSocket(0, InetAddress.getLoopbackAddress())) {
            collector.setSoTimeout(3_000);
            configure("SYSLOG_UDP", "127.0.0.1:" + collector.getLocalPort(), "LOW");

            mvc.perform(authenticated(post("/api/v1/api-keys"), asAdmin())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(write(Map.of("name", "ci-pipeline"))))
                    .andExpect(status().is2xxSuccessful());

            // Queued, not sent: nothing leaves on the request path.
            assertThat(siemRows()).isNotEmpty();
            assertThat(receive(collector, 300)).isEmpty();

            jobs.relayNotifications();

            List<String> received = receive(collector, 3_000);
            assertThat(received).anySatisfy(message -> assertThat(message)
                    .startsWith("<")
                    .contains(" vectispire - ZAN-SEC-012 - CEF:0|Vectispire|ASPM|")
                    .contains("|ZAN-SEC-012|API key issued|5|")
                    .contains("act=API_KEY_CREATED")
                    .contains("suser=admin-")
                    .contains("externalId="));
            // The save of the configuration itself is a security-relevant change, and says so.
            assertThat(received).anySatisfy(message -> assertThat(message).contains("|ZAN-SEC-019|"));
            assertThat(siemRows()).allSatisfy(row -> assertThat(row.getStatus()).isEqualTo("sent"));
        }
    }

    @Test
    @DisplayName("an event queued in a transaction that rolls back is never sent")
    void aRolledBackEventIsNotSent() throws Exception {
        try (DatagramSocket collector = new DatagramSocket(0, InetAddress.getLoopbackAddress())) {
            configure("SYSLOG_UDP", "127.0.0.1:" + collector.getLocalPort(), "LOW");
            outbox.deleteAll();

            transactions.executeWithoutResult(status -> {
                events.enqueue(kev("CVE-2026-0001"));
                status.setRollbackOnly();
            });
            jobs.relayNotifications();

            assertThat(siemRows()).isEmpty();
            assertThat(receive(collector, 500)).isEmpty();

            // The same event, committed, is: the difference is the transaction and nothing else.
            transactions.executeWithoutResult(status -> events.enqueue(kev("CVE-2026-0002")));
            jobs.relayNotifications();
            assertThat(receive(collector, 3_000)).singleElement().asString().contains("cs3=CVE-2026-0002");
        }
    }

    @Test
    @DisplayName("queueing outside a transaction is refused rather than committed on its own")
    void enqueueNeedsTheCallersTransaction() throws Exception {
        configure("SYSLOG_UDP", "127.0.0.1:9", "LOW");

        assertThatThrownBy(() -> events.enqueue(kev("CVE-2026-0003")))
                .isInstanceOf(IllegalTransactionStateException.class);
    }

    @Test
    @DisplayName("a collector that is down gets the event later, with the outbox's backoff")
    void aFailedDeliveryIsRetried() throws Exception {
        int port;
        try (ServerSocket probe = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            port = probe.getLocalPort();
        }
        configure("SYSLOG_TCP", "127.0.0.1:" + port, "LOW");
        outbox.deleteAll();

        transactions.executeWithoutResult(status -> events.enqueue(kev("CVE-2026-0004")));
        jobs.relayNotifications();

        OutboxMessageEntity failed = siemRows().getFirst();
        assertThat(failed.getStatus()).isEqualTo("pending");
        assertThat(failed.getAttempts()).isEqualTo(1);
        assertThat(failed.getLastError()).contains("unreachable");
        assertThat(failed.getNextAttemptAt()).isNotNull();

        try (ServerSocket collector = new ServerSocket(port, 1, InetAddress.getLoopbackAddress())) {
            CompletableFuture<byte[]> frame = CompletableFuture.supplyAsync(() -> readAll(collector));
            // The backoff is a minute; the test brings the next attempt forward rather than waiting.
            outbox.recordAttempt(failed.getId(), 1, failed.getLastError(), "pending", null);

            jobs.relayNotifications();

            String received = new String(frame.get(10, TimeUnit.SECONDS), StandardCharsets.UTF_8);
            // Octet-counted: the length, a space, then the RFC 5424 message.
            assertThat(received).matches("(?s)\\d+ <82>1 .*")
                    .contains("externalId=" + failed.getId())
                    .contains("cs3=CVE-2026-0004");
            OutboxMessageEntity sent = outbox.findById(failed.getId()).orElseThrow();
            assertThat(sent.getStatus()).isEqualTo("sent");
            assertThat(sent.getAttempts()).isEqualTo(2);
        }
    }

    @Test
    @DisplayName("the minimum severity decides what is queued at all")
    void theSeverityFilterApplies() throws Exception {
        configure("SYSLOG_UDP", "127.0.0.1:9", "CRITICAL");
        outbox.deleteAll();

        mvc.perform(authenticated(post("/api/v1/api-keys"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("name", "below-the-threshold"))))
                .andExpect(status().is2xxSuccessful());
        assertThat(siemRows()).isEmpty();

        transactions.executeWithoutResult(status -> events.enqueue(kev("CVE-2026-0005")));
        assertThat(siemRows()).hasSize(1);
    }

    @Test
    @DisplayName("an export switched off after an event was queued abandons it at once, saying why")
    void aDisabledExportAbandonsWhatWasQueued() throws Exception {
        configure("SYSLOG_UDP", "127.0.0.1:9", "LOW");
        outbox.deleteAll();
        transactions.executeWithoutResult(status -> events.enqueue(kev("CVE-2026-0006")));

        mvc.perform(authenticated(put("/api/v1/siem/config"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"enabled": false, "protocol": "SYSLOG_UDP", "endpoint": "127.0.0.1:9", "minSeverity": "LOW"}"""))
                .andExpect(status().isOk());
        jobs.relayNotifications();

        OutboxMessageEntity abandoned = siemRows().getFirst();
        assertThat(abandoned.getStatus()).isEqualTo("failed");
        assertThat(abandoned.getAttempts()).isLessThan(OutboxRetry.MAX_ATTEMPTS);
        assertThat(abandoned.getLastError()).contains("switched off");
    }

    private void configure(String protocol, String endpoint, String minSeverity) throws Exception {
        settings.set(Setting.NOTIFICATION_ALLOW_PRIVATE_URL, "true");
        mvc.perform(authenticated(put("/api/v1/siem/config"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"enabled": true, "protocol": "%s", "endpoint": "%s", "minSeverity": "%s"}"""
                                .formatted(protocol, endpoint, minSeverity)))
                .andExpect(status().isOk());
    }

    private List<OutboxMessageEntity> siemRows() {
        return outbox.findAll().stream().filter(row -> SiemEvents.TYPE.equals(row.getMessageType())).toList();
    }

    private static CefEvent kev(String cve) {
        return CefEvent.builder(SecurityEventType.CRITICAL_KEV_DETECTED).identifier(cve).build();
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

    private static byte[] readAll(ServerSocket listener) {
        try (Socket accepted = listener.accept(); InputStream in = accepted.getInputStream()) {
            accepted.setSoTimeout(5_000);
            return in.readAllBytes();
        } catch (Exception failed) {
            throw new IllegalStateException(failed);
        }
    }
}
