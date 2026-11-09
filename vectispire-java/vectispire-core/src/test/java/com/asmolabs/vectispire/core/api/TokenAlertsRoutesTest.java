package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.crypto.SecretCipher;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogEntity;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogRepository;
import com.asmolabs.vectispire.core.crypto.EncryptionService;
import com.asmolabs.vectispire.core.forges.ForgeTokenWatch;
import com.asmolabs.vectispire.core.forges.persistence.ForgeConnectionEntity;
import com.asmolabs.vectispire.core.forges.persistence.ForgeConnectionRepository;
import com.asmolabs.vectispire.core.maintenance.internal.MaintenanceJobs;
import com.asmolabs.vectispire.core.notifications.internal.TokenAlertAudit;
import com.asmolabs.vectispire.core.notifications.internal.TokenAlertDelivery;
import com.asmolabs.vectispire.core.outbox.persistence.OutboxMessageEntity;
import com.asmolabs.vectispire.core.outbox.persistence.OutboxMessageRepository;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.siem.SiemEvents;
import com.asmolabs.vectispire.core.tickets.TicketService;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.MediaType;
import org.springframework.transaction.PlatformTransactionManager;

/**
 * An integration token's change of state, from the turn that notices it to the audit entry, the SIEM event and the
 * channels' rows — on MySQL, through the real outbox, mapper, audit chain and SIEM hook.
 *
 * <p><b>Why.</b> A token that lapsed was a word on a screen and a line in the server log, for as long as nobody
 * looked. What is asserted is the whole path a SOC and a channel depend on, and the two properties a careful reading
 * cannot see: the change is said once — the record that it was said is the database's, so a second turn and a
 * restarted instance say nothing — and nothing said carries the token.
 */
@DisplayName("a token's change of state, pushed")
class TokenAlertsRoutesTest extends ApiTestBase {

    /** Invented for this test; planted so that its absence from every message can be checked. */
    private static final String PLANTED = "glpat-PLANTEDtokenNOTREAL0123"; // gitleaks:allow

    @Autowired
    private ForgeConnectionRepository connections;

    @Autowired
    private ForgeTokenWatch watch;

    @Autowired
    private SettingsService settings;

    @Autowired
    private EncryptionService encryption;

    @Autowired
    private OutboxMessageRepository outbox;

    @Autowired
    private AuditLogRepository auditLog;

    @Autowired
    private MaintenanceJobs jobs;

    @Autowired
    private TicketService tickets;

    @Autowired
    private ApplicationEventPublisher events;

    @Autowired
    private PlatformTransactionManager transactions;

    @Autowired
    private Clock clock;

    @BeforeEach
    void channelsAndSiem() throws Exception {
        // Two channels configured, three not: a row for each configured one and none for the others. The addresses
        // do not resolve, so the relay's attempts fail and stay queued — the rows are what is asserted.
        settings.set(Setting.WEBHOOK_URL, "https://hooks.example.invalid/global");
        settings.set(Setting.SLACK_WEBHOOK_URL, "https://hooks.example.invalid/slack");
        settings.set(Setting.SIEM_ALLOW_PRIVATE_DESTINATION, "true");
        mvc.perform(authenticated(put("/api/v1/siem/config"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"enabled\": true, \"protocol\": \"SYSLOG_UDP\", \"endpoint\": \"127.0.0.1:9\", "
                                + "\"minSeverity\": \"LOW\"}"))
                .andExpect(status().isOk());
        outbox.deleteAll();
        auditLog.deleteAll();
    }

    @Test
    @DisplayName("a forge connection: expiring, expired, replaced — each said once, in the log, to the SOC and on each channel, never its token")
    void aForgeConnectionsLife() {
        ForgeConnectionEntity connection = connection("Platform GitLab", clock.instant().plus(Duration.ofDays(5)));

        watch.watch();
        watch.watch();
        // A restart: another instance of the watch, nothing in memory, the database's record read again.
        restarted().watch();

        assertThat(rows(TokenAlertAudit.TYPE)).as("one audit entry queued for the change").hasSize(1);
        assertThat(rows(TokenAlertDelivery.TYPE)).as("one row per configured channel, the others queued nothing")
                .map(row -> read(row).path("channel").asText()).containsExactlyInAnyOrder("webhook", "slack");

        jobs.relayNotifications();

        assertThat(entries(AuditOperation.INTEGRATION_TOKEN_EXPIRING)).singleElement().satisfies(entry -> {
            assertThat(entry.getResourceId()).isEqualTo(connection.getId().toString());
            assertThat(entry.getDescription()).contains("\"Platform GitLab\"").contains("expires on");
            assertThat(entry.getUserId()).as("nobody did this").isNull();
        });
        assertThat(siemEvents("INTEGRATION_TOKEN_EXPIRING")).singleElement()
                .satisfies(event -> assertThat(event.path("cefSeverity").asInt()).isEqualTo(4));

        // It lapses.
        connection.setTokenExpiresAt(clock.instant().minus(Duration.ofHours(1)));
        connections.save(connection);
        watch.watch();
        watch.watch();
        jobs.relayNotifications();
        assertThat(entries(AuditOperation.INTEGRATION_TOKEN_STOPPED)).singleElement()
                .satisfies(entry -> assertThat(entry.getDescription()).contains("expired on"));
        assertThat(siemEvents("INTEGRATION_TOKEN_STOPPED")).singleElement()
                .satisfies(event -> assertThat(event.path("cefSeverity").asInt()).isEqualTo(7));

        // The administrator replaces it; the probe stored the new token's expiry.
        connection.setTokenExpiresAt(clock.instant().plus(Duration.ofDays(365)));
        connections.save(connection);
        watch.watch();
        watch.watch();
        jobs.relayNotifications();
        assertThat(entries(AuditOperation.INTEGRATION_TOKEN_RESTORED)).singleElement()
                .satisfies(entry -> assertThat(entry.getDescription()).contains("works again"));
        assertThat(siemEvents("INTEGRATION_TOKEN_RESTORED")).singleElement()
                .satisfies(event -> assertThat(event.path("cefSeverity").asInt()).isEqualTo(2));

        assertThat(rows(TokenAlertAudit.TYPE)).hasSize(3);
        assertThat(rows(TokenAlertDelivery.TYPE)).hasSize(6);
        // Nothing queued and nothing recorded carries the token, in the clear or sealed.
        for (OutboxMessageEntity row : outbox.findAll()) {
            assertThat(row.getPayload()).doesNotContain(PLANTED).doesNotContain(connection.getToken());
        }
        for (AuditLogEntity entry : auditLog.findAll()) {
            assertThat(entry.getDescription()).doesNotContain(PLANTED).doesNotContain(connection.getToken());
        }
    }

    @Test
    @DisplayName("the tracker token: a declared expiry within fourteen days is said once, however many checks run")
    void theTrackerToken() {
        settings.set(Setting.TICKET_PROVIDER, "jira");
        settings.set(Setting.TICKET_PROJECT, "SEC");
        tickets.setToken(PLANTED);
        settings.set(Setting.TICKET_TOKEN_EXPIRES_ON,
                LocalDate.ofInstant(clock.instant().plus(Duration.ofDays(5)), ZoneOffset.UTC).toString());

        tickets.checkTokenIfDue();
        tickets.checkTokenIfDue();
        tickets.checkTokenNow();

        assertThat(rows(TokenAlertAudit.TYPE)).hasSize(1);
        jobs.relayNotifications();
        assertThat(entries(AuditOperation.INTEGRATION_TOKEN_EXPIRING)).singleElement().satisfies(entry -> {
            assertThat(entry.getResourceId()).isEqualTo(Setting.TICKET_TOKEN.key());
            assertThat(entry.getDescription()).startsWith("The tracker token (Jira").doesNotContain(PLANTED);
        });
        assertThat(siemEvents("INTEGRATION_TOKEN_EXPIRING")).hasSize(1);
        for (OutboxMessageEntity row : outbox.findAll()) {
            assertThat(row.getPayload()).doesNotContain(PLANTED);
        }
    }

    @Test
    @DisplayName("the record moves only from the value its writer read: of two instances, the one that read before the other wrote is told no")
    void theConditionalUpdateArbitrates() {
        String key = "forge_token_announced:" + UUID.randomUUID();
        settings.storeInternalIfAbsent(key, "");

        // Both instances read "" — nothing said. The first moves it; the second, still holding "", is refused.
        assertThat(settings.replaceInternal(key, "", "expired")).isTrue();
        assertThat(settings.replaceInternal(key, "", "expired")).isFalse();
        assertThat(settings.internalValue(key)).contains("expired");
        assertThat(settings.replaceInternal(key, "expired", "none")).isTrue();
    }

    @Test
    @DisplayName("a deleted connection takes what was said of its token with it")
    void aDeletedConnectionForgetsItsRecord() throws Exception {
        ForgeConnectionEntity connection = connection("Short-lived", clock.instant().plus(Duration.ofDays(3)));
        watch.watch();
        String key = "forge_token_announced:" + connection.getId();
        assertThat(settings.internalValue(key)).contains("expires_soon");

        mvc.perform(authenticated(delete("/api/v1/forge-connections/" + connection.getId()), asAdmin()))
                .andExpect(status().is2xxSuccessful());

        assertThat(settings.internalValue(key)).isEmpty();
    }

    private ForgeConnectionEntity connection(String name, Instant expiresAt) {
        Instant now = clock.instant();
        UUID id = UUID.randomUUID();
        ForgeConnectionEntity entity = new ForgeConnectionEntity();
        entity.setId(id);
        entity.setName(name);
        entity.setKind("gitlab");
        entity.setEdition("gitlab_self_managed");
        entity.setBaseUrl("https://gitlab.example.com");
        entity.setInternalNetwork(false);
        entity.setToken(encryption.encrypt(PLANTED, SecretCipher.forgeConnectionContext(id.toString())));
        entity.setCredentialKind("gitlab_bot");
        entity.setTokenExpiresAt(expiresAt);
        entity.setProbedAt(now);
        entity.setCreatedAt(now);
        entity.setCreatedBy("admin");
        entity.setUpdatedAt(now);
        entity.setUpdatedBy("admin");
        return connections.save(entity);
    }

    private ForgeTokenWatch restarted() {
        return new ForgeTokenWatch(connections, settings, events, clock, transactions);
    }

    private List<OutboxMessageEntity> rows(String type) {
        return outbox.findAll().stream().filter(row -> type.equals(row.getMessageType())).toList();
    }

    private List<AuditLogEntity> entries(AuditOperation operation) {
        return auditLog.findAll().stream().filter(entry -> operation.wireName().equals(entry.getOperationType())).toList();
    }

    private List<JsonNode> siemEvents(String eventType) {
        return rows(SiemEvents.TYPE).stream().map(this::read)
                .filter(event -> eventType.equals(event.path("eventType").asText())).toList();
    }

    private JsonNode read(OutboxMessageEntity row) {
        try {
            return json.readTree(row.getPayload());
        } catch (Exception unreadable) {
            throw new IllegalStateException(unreadable);
        }
    }
}
