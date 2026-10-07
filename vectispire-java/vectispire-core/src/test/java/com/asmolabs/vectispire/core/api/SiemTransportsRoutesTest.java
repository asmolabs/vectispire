package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.integrations.Integration;
import com.asmolabs.vectispire.common.domain.integrations.IntegrationDisabledException;
import com.asmolabs.vectispire.common.domain.integrations.IntegrationInUseException;
import com.asmolabs.vectispire.common.domain.notifications.OutboxRetry;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.siem.CefEvent;
import com.asmolabs.vectispire.common.domain.siem.SecurityEventType;
import com.asmolabs.vectispire.common.domain.siem.SiemProtocol;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.audit.RequestActor;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogRepository;
import com.asmolabs.vectispire.core.maintenance.internal.MaintenanceJobs;
import com.asmolabs.vectispire.core.outbox.persistence.OutboxMessageEntity;
import com.asmolabs.vectispire.core.outbox.persistence.OutboxMessageRepository;
import com.asmolabs.vectispire.core.settings.Integrations;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.siem.SiemEvents;
import com.asmolabs.vectispire.core.siem.SiemExporterService;
import com.asmolabs.vectispire.core.siem.persistence.SiemConfigEntity;
import com.asmolabs.vectispire.core.siem.persistence.SiemConfigRepository;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * The SIEM transports as integrations (decision 0040, lot I3), through the real routes, registry, outbox
 * and database: the transport an enabled export sends over cannot be switched off; a disabled one is
 * neither configured nor tested; and an event whose transport is off — a row written by hand — waits in
 * the outbox rather than being sent or lost.
 *
 * <p>{@code t_integration} is not emptied between tests; each case puts its rows back ({@link
 * IntegrationRows}). Two cases force the interleavings the registry's lock exists for, with latches: the
 * race needs one, and a barrage of concurrent requests would pass with the lock removed.
 */
@DisplayName("SIEM transports as integrations, through the routes")
class SiemTransportsRoutesTest extends ApiTestBase {

    private static final String IN_USE = "urn:vectispire:problem:integration-in-use";
    private static final String DISABLED = "urn:vectispire:problem:integration-disabled";
    private static final Integration UDP = Integration.of(SiemProtocol.SYSLOG_UDP);
    private static final Integration TCP = Integration.of(SiemProtocol.SYSLOG_TCP);
    private static final Integration TLS = Integration.of(SiemProtocol.SYSLOG_TLS);
    private static final RequestActor ACTOR = new RequestActor("siem-transports-test", null, null);

    @Autowired
    private Integrations integrations;

    @Autowired
    private SiemExporterService exporter;

    @Autowired
    private SiemConfigRepository configs;

    @Autowired
    private SiemEvents events;

    @Autowired
    private MaintenanceJobs jobs;

    @Autowired
    private OutboxMessageRepository outbox;

    @Autowired
    private AuditLogRepository auditLog;

    @Autowired
    private SettingsService settings;

    @Autowired
    private TransactionTemplate transactions;

    @Autowired
    private JdbcTemplate jdbc;

    private IntegrationRows rows;
    private ExecutorService threads;

    @BeforeEach
    void remember() {
        rows = IntegrationRows.remember(jdbc);
        threads = Executors.newFixedThreadPool(2);
        settings.set(Setting.SIEM_ALLOW_PRIVATE_DESTINATION, "true");
    }

    @AfterEach
    void putBack() throws Exception {
        threads.shutdownNow();
        assertThat(threads.awaitTermination(30, TimeUnit.SECONDS)).isTrue();
        rows.putBack();
    }

    @Test
    @DisplayName("disabling the transport the export sends over is refused 409 integration-in-use: nothing changed, nothing audited")
    void theTransportInUseIsNotDisabled() throws Exception {
        save(true, "SYSLOG_UDP", "127.0.0.1:9").andExpect(status().isOk());
        Map<String, Object> before = row(UDP);

        ResultActions refused = disable(UDP).andExpect(status().isConflict())
                .andExpect(jsonPath("$.type").value(IN_USE))
                .andExpect(jsonPath("$.integration").value("siem.syslog_udp"));
        assertThat(detailOf(refused.andReturn()))
                .startsWith("The integration \"siem.syslog_udp\" is in use and cannot be disabled")
                .contains("Change the SIEM configuration first")
                .contains("lost in silence");

        assertThat(integrations.isEnabled(UDP)).isTrue();
        assertThat(row(UDP)).as("not touched: neither the state nor who switched it").isEqualTo(before);
        assertThat(switchesAudited()).isZero();
    }

    @Test
    @DisplayName("disabling a transport the export does not use goes through")
    void anotherTransportIsDisabled() throws Exception {
        save(true, "SYSLOG_UDP", "127.0.0.1:9").andExpect(status().isOk());

        disable(TLS).andExpect(status().isOk()).andExpect(jsonPath("$.enabled").value(false));
        disable(Integration.of(SiemProtocol.WEBHOOK)).andExpect(status().isOk());

        assertThat(integrations.isEnabled(TLS)).isFalse();
        assertThat(integrations.isEnabled(UDP)).isTrue();
        assertThat(switchesAudited()).isEqualTo(2);
    }

    @Test
    @DisplayName("once the export is pointed at another transport, or switched off, the old one may be disabled")
    void theOldTransportIsReleased() throws Exception {
        save(true, "SYSLOG_UDP", "127.0.0.1:9").andExpect(status().isOk());
        disable(UDP).andExpect(status().isConflict());

        save(true, "SYSLOG_TCP", "127.0.0.1:9").andExpect(status().isOk());
        disable(UDP).andExpect(status().isOk());
        disable(TCP).andExpect(status().isConflict()).andExpect(jsonPath("$.integration").value("siem.syslog_tcp"));

        // A disabled export uses no transport, whatever protocol its row still names.
        save(false, "SYSLOG_TCP", "127.0.0.1:9").andExpect(status().isOk());
        disable(TCP).andExpect(status().isOk());
        assertThat(integrations.isEnabled(UDP)).isFalse();
        assertThat(integrations.isEnabled(TCP)).isFalse();
    }

    @Test
    @DisplayName("an enabled export is not saved over a disabled transport, nor is one tested: 409 integration-disabled, nothing sent")
    void aDisabledTransportIsNeitherConfiguredNorTested() throws Exception {
        save(true, "SYSLOG_TCP", "127.0.0.1:9").andExpect(status().isOk());
        SiemConfigEntity before = configs.findById(SiemConfigEntity.SINGLETON_ID).orElseThrow();
        disable(UDP).andExpect(status().isOk());

        try (DatagramSocket collector = new DatagramSocket(0, InetAddress.getLoopbackAddress())) {
            String endpoint = "127.0.0.1:" + collector.getLocalPort();

            assertThat(detailOf(save(true, "SYSLOG_UDP", endpoint).andExpect(status().isConflict())
                            .andExpect(jsonPath("$.type").value(DISABLED))
                            .andExpect(jsonPath("$.integration").value("siem.syslog_udp")).andReturn()))
                    .contains("\"siem.syslog_udp\" is disabled");
            // Before the form's other words: the endpoint would be refused too, and correcting it would not help.
            save(true, "SYSLOG_UDP", "https://collector.example.com/events").andExpect(status().isConflict())
                    .andExpect(jsonPath("$.type").value(DISABLED));
            SiemConfigEntity after = configs.findById(SiemConfigEntity.SINGLETON_ID).orElseThrow();
            assertThat(after.getProtocol()).isEqualTo("SYSLOG_TCP");
            assertThat(after.getUpdatedAt()).isEqualTo(before.getUpdatedAt());

            test(Map.of("protocol", "SYSLOG_UDP", "endpoint", endpoint)).andExpect(status().isConflict())
                    .andExpect(jsonPath("$.type").value(DISABLED))
                    .andExpect(jsonPath("$.integration").value("siem.syslog_udp"));
            assertThat(receive(collector, 500)).as("nothing went out over the disabled transport").isEmpty();
        }
    }

    @Test
    @DisplayName("a disabled export is saved over a disabled transport; the test of its stored protocol is still refused")
    void aDisabledExportIsSavedOverAnyTransport() throws Exception {
        disable(UDP).andExpect(status().isOk());

        save(false, "SYSLOG_UDP", "127.0.0.1:9").andExpect(status().isOk())
                .andExpect(jsonPath("$.enabled").value(false))
                .andExpect(jsonPath("$.protocol").value("SYSLOG_UDP"));

        // No protocol on the form: the stored one is tested, and it is off.
        test(Map.of("endpoint", "127.0.0.1:9")).andExpect(status().isConflict())
                .andExpect(jsonPath("$.type").value(DISABLED));
        // Switched on, it is refused until the transport is.
        save(true, "SYSLOG_UDP", "127.0.0.1:9").andExpect(status().isConflict());
        integrations.switchTo(UDP, true, "governor");
        save(true, "SYSLOG_UDP", "127.0.0.1:9").andExpect(status().isOk());
    }

    @Test
    @DisplayName("an event over a transport switched off by hand is held — pending, uncounted, never abandoned — and leaves once it is on")
    void theSenderHoldsWhatItMayNotSend() throws Exception {
        try (DatagramSocket collector = new DatagramSocket(0, InetAddress.getLoopbackAddress())) {
            save(true, "SYSLOG_UDP", "127.0.0.1:" + collector.getLocalPort()).andExpect(status().isOk());
            outbox.deleteAll();
            transactions.executeWithoutResult(status -> events.enqueue(kev("CVE-2026-0101")));
            // Past the registry, as a row written by SQL — or a race the lock did not exist to close — would be.
            jdbc.update("update t_integration set enabled = ? where integration_key = ?", false, UDP.key());

            Instant beforeRelay = Instant.now();
            jobs.relayNotifications();

            OutboxMessageEntity held = siemRows().getFirst();
            assertThat(held.getStatus()).isEqualTo("pending");
            assertThat(held.getAttempts()).as("no attempt counted").isZero();
            assertThat(held.getSentAt()).isNull();
            assertThat(held.getLastError()).contains("siem.syslog_udp").contains("is disabled").contains("waits");
            assertThat(held.getNextAttemptAt()).isAfter(beforeRelay.plus(OutboxRetry.HOLD_INTERVAL).minusSeconds(60));
            assertThat(receive(collector, 500)).isEmpty();

            // More passes than the attempts that abandon a failing message: a hold never becomes a loss.
            for (int pass = 0; pass <= OutboxRetry.MAX_ATTEMPTS; pass++) {
                outbox.recordAttempt(held.getId(), 0, held.getLastError(), "pending", null);
                jobs.relayNotifications();
            }
            OutboxMessageEntity still = outbox.findById(held.getId()).orElseThrow();
            assertThat(still.getStatus()).isEqualTo("pending");
            assertThat(still.getAttempts()).isZero();
            assertThat(receive(collector, 300)).isEmpty();

            integrations.switchTo(UDP, true, "governor");
            outbox.recordAttempt(held.getId(), 0, held.getLastError(), "pending", null);
            jobs.relayNotifications();

            assertThat(receive(collector, 3_000)).singleElement().asString().contains("cs3=CVE-2026-0101");
            OutboxMessageEntity sent = outbox.findById(held.getId()).orElseThrow();
            assertThat(sent.getStatus()).isEqualTo("sent");
            assertThat(sent.getAttempts()).isOne();
        }
    }

    @Test
    @DisplayName("the stop notice is not sent over a transport switched off by hand, and the audit entry says so")
    void theStopNoticeIsNotSentOverADisabledTransport() throws Exception {
        try (DatagramSocket collector = new DatagramSocket(0, InetAddress.getLoopbackAddress())) {
            String endpoint = "127.0.0.1:" + collector.getLocalPort();
            save(true, "SYSLOG_UDP", endpoint).andExpect(status().isOk());
            jdbc.update("update t_integration set enabled = ? where integration_key = ?", false, UDP.key());

            save(false, "SYSLOG_UDP", endpoint).andExpect(status().isOk());

            assertThat(receive(collector, 500)).isEmpty();
            assertThat(auditLog.findAllByOrderByTimestampAscIdAsc().stream()
                    .map(entry -> entry.getDescription())
                    .filter(description -> description != null && description.startsWith("SIEM configuration updated"))
                    .reduce((first, second) -> second).orElseThrow())
                    .contains("enabled=false")
                    .contains("stop notice NOT sent to the previous collector: its transport siem.syslog_udp is disabled");
        }
    }

    @Test
    @DisplayName("a switch arriving while a save holds the transport waits for it, then sees it in use")
    void aSwitchWaitsForTheSaveThatHoldsTheTransport() throws Exception {
        save(true, "SYSLOG_TCP", "127.0.0.1:9").andExpect(status().isOk());
        CountDownLatch holding = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);

        // The save's transaction, stopped between taking the transport and writing the row that uses it.
        Future<?> saving = threads.submit(() -> transactions.executeWithoutResult(status -> {
            integrations.holdEnabled(UDP);
            holding.countDown();
            await(release);
            SiemConfigEntity row = configs.findById(SiemConfigEntity.SINGLETON_ID).orElseThrow();
            row.setProtocol("SYSLOG_UDP");
            configs.save(row);
        }));
        assertThat(holding.await(10, TimeUnit.SECONDS)).isTrue();

        Future<Integrations.Switched> switching = threads.submit(() -> integrations.switchTo(UDP, false, "governor"));
        assertThatThrownBy(() -> switching.get(1_000, TimeUnit.MILLISECONDS))
                .as("the switch waits for the save").isInstanceOf(TimeoutException.class);

        release.countDown();
        saving.get(30, TimeUnit.SECONDS);
        assertThatThrownBy(() -> switching.get(30, TimeUnit.SECONDS))
                .isInstanceOf(ExecutionException.class).hasCauseInstanceOf(IntegrationInUseException.class);
        assertThat(integrations.isEnabled(UDP)).isTrue();
        assertThat(configs.findById(SiemConfigEntity.SINGLETON_ID).orElseThrow().getProtocol()).isEqualTo("SYSLOG_UDP");
    }

    @Test
    @DisplayName("a save arriving while a switch is still open waits for it, then reads the transport off")
    void aSaveWaitsForTheSwitch() throws Exception {
        save(true, "SYSLOG_TCP", "127.0.0.1:9").andExpect(status().isOk());
        CountDownLatch switched = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);

        // The governor's switch, done and not yet committed.
        Future<?> switching = threads.submit(() -> transactions.executeWithoutResult(status -> {
            assertThat(integrations.switchTo(UDP, false, "governor").changed()).isTrue();
            switched.countDown();
            await(release);
        }));
        assertThat(switched.await(10, TimeUnit.SECONDS)).isTrue();

        Future<?> saving = threads.submit(() -> exporter.saveConfig(true, "SYSLOG_UDP", "127.0.0.1:9", null, "LOW", null,
                ACTOR));
        assertThatThrownBy(() -> saving.get(1_000, TimeUnit.MILLISECONDS))
                .as("the save waits for the switch").isInstanceOf(TimeoutException.class);

        release.countDown();
        switching.get(30, TimeUnit.SECONDS);
        assertThatThrownBy(() -> saving.get(30, TimeUnit.SECONDS))
                .isInstanceOf(ExecutionException.class).hasCauseInstanceOf(IntegrationDisabledException.class);
        assertThat(integrations.isEnabled(UDP)).isFalse();
        assertThat(configs.findById(SiemConfigEntity.SINGLETON_ID).orElseThrow().getProtocol()).isEqualTo("SYSLOG_TCP");
    }

    private ResultActions save(boolean enabled, String protocol, String endpoint) throws Exception {
        return mvc.perform(authenticated(put("/api/v1/siem/config"), asAdmin())
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"enabled": %s, "protocol": "%s", "endpoint": "%s", "minSeverity": "LOW"}"""
                        .formatted(enabled, protocol, endpoint)));
    }

    private ResultActions test(Map<String, String> body) throws Exception {
        return mvc.perform(authenticated(post("/api/v1/siem/test"), asAdmin())
                .contentType(MediaType.APPLICATION_JSON).content(write(body)));
    }

    private ResultActions disable(Integration integration) throws Exception {
        return mvc.perform(authenticated(put("/api/v1/integrations/" + integration.key() + "/enabled"),
                        tokenFor("governor-" + System.nanoTime(), Role.SUPERUSER, false))
                .contentType(MediaType.APPLICATION_JSON).content(write(Map.of("enabled", false))));
    }

    private Map<String, Object> row(Integration integration) {
        return jdbc.queryForMap("select enabled, updated_at, updated_by from t_integration where integration_key = ?",
                integration.key());
    }

    private long switchesAudited() {
        return auditLog.findAll().stream()
                .filter(entry -> AuditOperation.INTEGRATION_ENABLED_CHANGED.wireName().equals(entry.getOperationType()))
                .count();
    }

    private List<OutboxMessageEntity> siemRows() {
        return outbox.findAll().stream().filter(row -> SiemEvents.TYPE.equals(row.getMessageType())).toList();
    }

    private static CefEvent kev(String cve) {
        return CefEvent.builder(SecurityEventType.CRITICAL_KEV_DETECTED).identifier(cve).build();
    }

    private static void await(CountDownLatch latch) {
        try {
            if (!latch.await(30, TimeUnit.SECONDS)) {
                throw new IllegalStateException("never released");
            }
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(interrupted);
        }
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
}
