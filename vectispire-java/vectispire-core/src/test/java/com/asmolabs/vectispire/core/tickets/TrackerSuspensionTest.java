package com.asmolabs.vectispire.core.tickets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.crypto.EncryptionKey;
import com.asmolabs.vectispire.common.domain.dependencies.Directness;
import com.asmolabs.vectispire.common.domain.exports.ExportableIssue.FixState;
import com.asmolabs.vectispire.common.domain.integrations.Integration;
import com.asmolabs.vectispire.common.domain.integrations.IntegrationDisabledException;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.net.OutboundUrlGuard;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.tickets.TicketProvider;
import com.asmolabs.vectispire.common.domain.tickets.Tickets.TicketableIssue;
import com.asmolabs.vectispire.common.domain.tickets.TrackerState;
import com.asmolabs.vectispire.core.crypto.EncryptionService;
import com.asmolabs.vectispire.core.crypto.internal.EncryptionProperties;
import com.asmolabs.vectispire.core.forges.ForgeStub;
import com.asmolabs.vectispire.core.forges.ForgeStub.Reply;
import com.asmolabs.vectispire.core.outbound.OutboundJson;
import com.asmolabs.vectispire.core.outbound.OutboundPost;
import com.asmolabs.vectispire.core.outbound.PinnedHttpSender;
import com.asmolabs.vectispire.core.settings.Integrations;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * A tracker whose integration the governor switched off (decision 0040 §3, lot I6): suspended, not unconfigured.
 *
 * <p><b>Why.</b> Before I6 the registry recorded the switch of a {@code tracker.*} integration and nothing read it:
 * the hourly sweep went on opening and closing tickets, the daily check went on asking the tracker about its token,
 * and saving a token probed the tracker — all with the token of an integration the governor had said this
 * installation does not talk to. The tracker here is {@link ForgeStub}, real TLS through the pinned CA, so that "no
 * call reaches the tracker" is read off what the tracker saw, not off a mock that was not called.
 */
@DisplayName("the tracker client while its integration is disabled")
class TrackerSuspensionTest {

    private static final String ISSUES = "/api/v4/projects/team%2Fservice/issues";
    private static final String SELF = "/api/v4/personal_access_tokens/self";
    private static final Instant NOW = Instant.parse("2026-10-13T08:00:00Z");
    private static final Integration GITLAB = Integration.of(TicketProvider.GITLAB);

    private ForgeStub tracker;
    private final Map<String, String> rows = new ConcurrentHashMap<>();
    private final AtomicBoolean enabled = new AtomicBoolean(false);
    private String storedToken;
    private TicketService service;

    @BeforeEach
    void start() throws Exception {
        tracker = ForgeStub.start()
                .route(ISSUES, Reply.json("{\"iid\":7,\"web_url\":\"https://gitlab.internal/team/service/-/issues/7\"}"))
                .route(ISSUES + "/7", Reply.json("{}"))
                // Inside the fourteen days' notice: what the daily check announces once it may ask.
                .route(SELF, Reply.json("{\"active\":true,\"expires_at\":\"2026-10-20\"}"));
        EncryptionService encryption =
                new EncryptionService(new EncryptionProperties(Optional.of(EncryptionKey.generate()), List.of()));
        SettingsService settings = mock(SettingsService.class);
        when(settings.get(any())).thenAnswer(call -> {
            Setting setting = call.getArgument(0);
            return rows.getOrDefault(setting.key(), setting.defaultValue());
        });
        when(settings.isEnabled(any())).thenAnswer(call -> "true".equals(settings.get(call.getArgument(0))));
        when(settings.internalValue(anyString())).thenAnswer(call -> Optional.ofNullable(rows.get(call.<String>getArgument(0))));
        doAnswer(call -> rows.put(call.getArgument(0), call.getArgument(1))).when(settings).setInternal(anyString(), anyString());
        // 0.11.1 announces through a conditional update (one instance says it): answered as the table does.
        when(settings.storeInternalIfAbsent(anyString(), anyString()))
                .thenAnswer(call -> rows.putIfAbsent(call.getArgument(0), call.getArgument(1)) == null);
        when(settings.replaceInternal(anyString(), anyString(), anyString()))
                .thenAnswer(call -> rows.replace(call.getArgument(0), call.getArgument(1), call.getArgument(2)));
        doAnswer(call -> rows.put(call.<Setting>getArgument(0).key(), call.getArgument(1)))
                .when(settings).set(any(), anyString());

        storedToken = encryption.encrypt("glpat-internal", TicketService.TOKEN_CONTEXT);
        rows.put(Setting.TICKET_PROVIDER.key(), TicketProvider.GITLAB.wireName());
        rows.put(Setting.TICKET_BASE_URL.key(), tracker.baseUrl());
        rows.put(Setting.TICKET_PROJECT.key(), "team/service");
        rows.put(Setting.TICKET_ALLOW_PRIVATE_URL.key(), "true");
        rows.put(Setting.TICKET_CA.key(), tracker.caPem);
        rows.put(Setting.TICKET_TOKEN.key(), storedToken);

        // The registry the governor switches: off until a case turns it on.
        Integrations registry = mock(Integrations.class);
        when(registry.isEnabled(any())).thenAnswer(call -> GITLAB.equals(call.getArgument(0)) && enabled.get());

        ObjectMapper json = new ObjectMapper();
        OutboundUrlGuard guard = new OutboundUrlGuard();
        PinnedHttpSender sender = new PinnedHttpSender();
        service = new TicketService(settings, encryption, new OutboundPost(sender, guard, json),
                new OutboundJson(sender, guard, json), json, Clock.fixed(NOW, ZoneOffset.UTC),
                new TrackerTokenState(settings, event -> {}, org.springframework.transaction.support.TransactionOperations.withoutTransaction()), registry);
    }

    @AfterEach
    void stop() {
        tracker.close();
    }

    @Test
    @DisplayName("is configured, not enabled, and reads suspended under its integration's key")
    void readsSuspended() {
        assertThat(service.isConfigured()).as("nothing of its configuration is lost").isTrue();
        assertThat(service.isEnabled()).isFalse();
        assertThat(service.standing()).hasValueSatisfying(standing -> {
            assertThat(standing.integration().key()).isEqualTo("tracker.gitlab");
            assertThat(standing.state()).isEqualTo(TrackerState.SUSPENDED);
        });

        enabled.set(true);

        assertThat(service.isEnabled()).isTrue();
        assertThat(service.standing()).map(TicketService.Standing::state).contains(TrackerState.ACTIVE);
    }

    @Test
    @DisplayName("opens no ticket: nothing reaches the tracker, and switched back on it opens one")
    void opensNothing() {
        assertThat(service.createForIssue(issue(), "team/service")).isEmpty();
        assertThat(tracker.seen).as("no call reached the tracker").isEmpty();

        enabled.set(true);

        assertThat(service.createForIssue(issue(), "team/service")).map(TicketService.Ticket::reference).contains("#7");
        assertThat(tracker.count(ISSUES)).isOne();
    }

    @Test
    @DisplayName("closes no ticket: nothing reaches the tracker, and switched back on it closes it")
    void closesNothing() {
        assertThat(service.closeTicket("#7", "clean scan")).isFalse();
        assertThat(tracker.seen).isEmpty();

        enabled.set(true);

        assertThat(service.closeTicket("#7", "clean scan")).isTrue();
        assertThat(tracker.count(ISSUES + "/7")).isOne();
    }

    @Test
    @DisplayName("the daily check asks nothing and announces nothing; switched back on, it asks")
    void theDailyCheckWaits() {
        // An expiry an administrator declared inside the notice window: what the check would announce.
        rows.put(Setting.TICKET_TOKEN_EXPIRES_ON.key(), "2026-10-20");

        service.checkTokenIfDue();

        assertThat(tracker.seen).isEmpty();
        assertThat(rows).as("a tracker switched off is not a token to announce")
                .doesNotContainKey(TrackerTokenState.ANNOUNCED)
                .doesNotContainKey(TrackerTokenState.CHECKED_AT);

        enabled.set(true);
        service.checkTokenIfDue();

        assertThat(tracker.count(SELF)).isOne();
        assertThat(rows).containsEntry(TrackerTokenState.ANNOUNCED, "expires_soon");
    }

    @Test
    @DisplayName("the probe when a token is saved stores it, asks nothing and reports no refusal")
    void theSaveProbeWaits() {
        rows.put(Setting.TICKET_TOKEN_EXPIRES_ON.key(), "2026-10-20");
        service.setToken("glpat-replaced");

        TrackerTokenState.Health health = service.checkTokenNow();

        assertThat(tracker.seen).as("not probed").isEmpty();
        assertThat(health.refused()).as("not \"stopped working\": nobody asked").isEmpty();
        assertThat(health.checkedAt()).isEmpty();
        assertThat(rows).as("nothing announced of a token nobody may use yet")
                .doesNotContainKey(TrackerTokenState.ANNOUNCED);
        assertThat(rows.get(Setting.TICKET_TOKEN.key())).as("stored all the same, encrypted")
                .isNotBlank().doesNotContain("glpat-replaced");

        enabled.set(true);

        assertThat(service.checkTokenNow().checkedAt()).contains(NOW);
        assertThat(tracker.seen).singleElement()
                .satisfies(request -> assertThat(request.headers()).containsEntry("private-token", "glpat-replaced"));
    }

    @Test
    @DisplayName("hands its token to nobody, and keeps it: the row is untouched and reads again once re-enabled")
    void theTokenStaysInItsRow() {
        assertThat(service.hasToken()).isTrue();
        assertThatThrownBy(service::token)
                .isInstanceOfSatisfying(IntegrationDisabledException.class,
                        refused -> assertThat(refused.integration()).isEqualTo(GITLAB));
        assertThat(rows).containsEntry(Setting.TICKET_TOKEN.key(), storedToken);

        enabled.set(true);

        assertThat(service.token()).isEqualTo("glpat-internal");
    }

    private static TicketableIssue issue() {
        return new TicketableIssue(
                1L, FindingType.VULNERABILITY, "CVE-2026-1", Severity.CRITICAL, "openssl", "3.5.1", "3.5.2",
                FixState.FIXED, Directness.DIRECT, null, null, true, 0.42, null, "A buffer overflow.", "abc");
    }
}
