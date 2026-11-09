package com.asmolabs.vectispire.core.tickets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.crypto.EncryptionKey;
import com.asmolabs.vectispire.common.domain.dependencies.Directness;
import com.asmolabs.vectispire.common.domain.exports.ExportableIssue.FixState;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.net.OutboundUrlGuard;
import com.asmolabs.vectispire.common.domain.notifications.TokenAlert;
import com.asmolabs.vectispire.common.domain.notifications.TokenAlert.Notice;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.tickets.TicketProvider;
import com.asmolabs.vectispire.common.domain.tickets.Tickets.TicketableIssue;
import com.asmolabs.vectispire.core.crypto.EncryptionService;
import com.asmolabs.vectispire.core.crypto.internal.EncryptionProperties;
import com.asmolabs.vectispire.core.forges.ForgeStub;
import com.asmolabs.vectispire.core.forges.ForgeStub.Reply;
import com.asmolabs.vectispire.core.outbound.OutboundJson;
import com.asmolabs.vectispire.core.outbound.OutboundPost;
import com.asmolabs.vectispire.core.outbound.PinnedHttpSender;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.tickets.TrackerTokenState.ExpirySource;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
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
 * The tracker token's expiry and refusal, learned from a tracker over real TLS and announced once per change.
 *
 * <p><b>Why.</b> GitLab forces an expiry on its tokens; the day one lapsed, the hourly sweep failed on every call
 * with a log line nobody read, for ever. The tracker here is {@link ForgeStub} — HTTPS with a throwaway CA, pinned
 * through the tracker CA setting — the sender, the guard and the pin are real, and the settings are a map, so that
 * what is written, and how many times, can be counted.
 */
@DisplayName("the tracker token's life")
class TrackerTokenCheckTest {

    private static final String SELF = "/api/v4/personal_access_tokens/self";
    private static final Instant START = Instant.parse("2026-10-12T08:00:00Z");

    private ForgeStub tracker;
    private final Map<String, String> rows = new ConcurrentHashMap<>();
    private SettingsService settings;
    private MovableClock clock;
    private TicketService service;
    private EncryptionService encryption;

    /** What was published, in order: the alerts {@code notifications} turns into an entry, an event and messages. */
    private final List<TokenAlert> published = new ArrayList<>();

    /** When set, the next conditional update finds the row moved — another instance said it first. */
    private final AtomicBoolean anotherInstanceFirst = new AtomicBoolean();

    @BeforeEach
    void start() throws Exception {
        tracker = ForgeStub.start();
        encryption =
                new EncryptionService(new EncryptionProperties(Optional.of(EncryptionKey.generate()), List.of()));
        settings = mock(SettingsService.class);
        when(settings.get(any())).thenAnswer(call -> {
            Setting setting = call.getArgument(0);
            return rows.getOrDefault(setting.key(), setting.defaultValue());
        });
        when(settings.isEnabled(any())).thenAnswer(call -> "true".equals(settings.get(call.getArgument(0))));
        when(settings.internalValue(anyString())).thenAnswer(call -> Optional.ofNullable(rows.get(call.<String>getArgument(0))));
        doAnswer(call -> rows.put(call.getArgument(0), call.getArgument(1))).when(settings).setInternal(anyString(), anyString());
        when(settings.storeInternalIfAbsent(anyString(), anyString()))
                .thenAnswer(call -> rows.putIfAbsent(call.getArgument(0), call.getArgument(1)) == null);
        // The conditional update, as the table answers it: moved only from the value its caller read.
        when(settings.replaceInternal(anyString(), anyString(), anyString())).thenAnswer(call -> {
            if (anotherInstanceFirst.getAndSet(false)) {
                rows.put(call.getArgument(0), call.getArgument(2));
                return false;
            }
            return rows.replace(call.getArgument(0), call.getArgument(1), call.getArgument(2));
        });
        doAnswer(call -> rows.put(call.<Setting>getArgument(0).key(), call.getArgument(1)))
                .when(settings).set(any(), anyString());

        rows.put(Setting.TICKET_PROVIDER.key(), TicketProvider.GITLAB.wireName());
        rows.put(Setting.TICKET_BASE_URL.key(), tracker.baseUrl());
        rows.put(Setting.TICKET_PROJECT.key(), "team/service");
        rows.put(Setting.TICKET_ALLOW_PRIVATE_URL.key(), "true");
        rows.put(Setting.TICKET_CA.key(), tracker.caPem);
        rows.put(Setting.TICKET_TOKEN.key(), encryption.encrypt("glpat-internal", TicketService.TOKEN_CONTEXT));

        clock = new MovableClock(START);
        ObjectMapper json = new ObjectMapper();
        OutboundUrlGuard guard = new OutboundUrlGuard();
        PinnedHttpSender sender = new PinnedHttpSender();
        service = new TicketService(settings, encryption, new OutboundPost(sender, guard, json),
                new OutboundJson(sender, guard, json), json, clock,
                new TrackerTokenState(settings, event -> published.add((TokenAlert) event),
                        org.springframework.transaction.support.TransactionOperations.withoutTransaction()), TrackerIntegrations.allEnabled());
    }

    @AfterEach
    void stop() {
        tracker.close();
    }

    @Test
    @DisplayName("GitLab's token description is read through the pinned CA, and its expiry kept as reported")
    void gitlabReportsTheExpiry() {
        tracker.route(SELF, Reply.json("{\"active\":true,\"revoked\":false,\"expires_at\":\"2027-01-31\"}"));

        TrackerTokenState.Health health = service.checkTokenNow();

        assertThat(health.expiresAt()).contains(Instant.parse("2027-01-31T00:00:00Z"));
        assertThat(health.expirySource()).isEqualTo(ExpirySource.REPORTED);
        assertThat(health.checkedAt()).contains(START);
        assertThat(tracker.seen).singleElement().satisfies(request -> {
            assertThat(request.path()).isEqualTo(SELF);
            assertThat(request.headers()).containsEntry("private-token", "glpat-internal");
        });
    }

    @Test
    @DisplayName("GitHub's expiry header is read off an authenticated call to the repository")
    void githubReportsTheExpiryInAHeader() {
        rows.put(Setting.TICKET_PROVIDER.key(), TicketProvider.GITHUB.wireName());
        tracker.route("/repos/team/service", Reply.json("{\"full_name\":\"team/service\"}")
                .with("github-authentication-token-expiration", "2026-10-20 12:00:00 UTC"));

        assertThat(service.checkTokenNow().expiresAt()).contains(Instant.parse("2026-10-20T12:00:00Z"));
    }

    @Test
    @DisplayName("fourteen days ahead it is announced once, and not again each day while nothing changes")
    void anExpiryInsideTheNoticeIsAnnouncedOnce() {
        tracker.route(SELF, Reply.json("{\"active\":true,\"expires_at\":\"" + LocalDate.ofInstant(START.plus(
                Duration.ofDays(10)), ZoneOffset.UTC) + "\"}"));

        service.checkTokenIfDue();
        clock.advance(Duration.ofHours(1));
        service.checkTokenIfDue();
        clock.advance(Duration.ofDays(1));
        service.checkTokenIfDue();

        // Asked once a day, not once an hour.
        assertThat(tracker.count(SELF)).isEqualTo(2);
        assertThat(rows).containsEntry(TrackerTokenState.ANNOUNCED, "expires_soon");
        verify(settings, times(1)).replaceInternal(TrackerTokenState.ANNOUNCED, "", "expires_soon");
        assertThat(published).singleElement().satisfies(alert -> {
            assertThat(alert.notice()).isEqualTo(Notice.EXPIRES_SOON);
            assertThat(alert.previous()).isEqualTo(Notice.NONE);
            assertThat(alert.credential()).isEqualTo(TokenAlert.Credential.TRACKER_TOKEN);
            assertThat(alert.expiresAt()).isEqualTo(LocalDate.ofInstant(START.plus(Duration.ofDays(10)), ZoneOffset.UTC)
                    .atStartOfDay(ZoneOffset.UTC).toInstant());
            // The provider's kind alone: the tracker's address is a secret setting, and the alert reaches the
            // audit log every auditor reads, the SIEM and every chat channel.
            assertThat(alert.where()).isEqualTo("GitLab");
        });
    }

    @Test
    @DisplayName("an expiry nobody acted on is announced as expired, once")
    void aPastExpiryIsAnnouncedOnce() {
        tracker.route(SELF, Reply.json("{\"active\":true,\"expires_at\":\"" + LocalDate.ofInstant(START.plus(
                Duration.ofDays(3)), ZoneOffset.UTC) + "\"}"));
        service.checkTokenIfDue();
        // The tracker no longer answers the expired token's description; the date it gave is what is known.
        tracker.route(SELF, Reply.status(500));

        clock.advance(Duration.ofDays(4));
        service.checkTokenIfDue();
        clock.advance(Duration.ofHours(1));
        service.checkTokenIfDue();

        verify(settings, times(1)).replaceInternal(TrackerTokenState.ANNOUNCED, "expires_soon", "expired");
        assertThat(published).extracting(TokenAlert::notice).containsExactly(Notice.EXPIRES_SOON, Notice.EXPIRED);
        assertThat(published.getLast().previous()).isEqualTo(Notice.EXPIRES_SOON);
    }

    @Test
    @DisplayName("a token the tracker refuses (401) is said to have stopped working once, and back to normal on the next success")
    void aRefusalIsAnnouncedOnceAndClearedBySuccess() {
        tracker.route("/api/v4/projects/team%2Fservice/issues", Reply.status(401));

        assertThat(service.createForIssue(issue(), "team/service")).isEmpty();
        clock.advance(Duration.ofHours(1));
        assertThat(service.createForIssue(issue(), "team/service")).isEmpty();

        TrackerTokenState.Health refused = service.tokenHealth();
        assertThat(refused.refused()).hasValueSatisfying(refusal -> {
            assertThat(refusal.status()).isEqualTo(401);
            // Dated when it began, not when it was last met.
            assertThat(refusal.since()).isEqualTo(START);
        });
        verify(settings, times(1)).replaceInternal(TrackerTokenState.ANNOUNCED, "", "refused");
        assertThat(published).singleElement().satisfies(alert -> {
            assertThat(alert.notice()).isEqualTo(Notice.REFUSED);
            assertThat(alert.refusedStatus()).isEqualTo(401);
            assertThat(alert.refusedSince()).isEqualTo(START);
        });

        tracker.route("/api/v4/projects/team%2Fservice/issues", Reply.json("{\"iid\":7,\"web_url\":\"x\"}"));
        assertThat(service.createForIssue(issue(), "team/service")).isPresent();

        assertThat(service.tokenHealth().refused()).isEmpty();
        assertThat(rows).containsEntry(TrackerTokenState.ANNOUNCED, "none");
        assertThat(published).extracting(TokenAlert::notice).containsExactly(Notice.REFUSED, Notice.NONE);
        assertThat(published.getLast().previous()).isEqualTo(Notice.REFUSED);
        assertThat(published.getLast().sentence()).endsWith("works again.");
    }

    @Test
    @DisplayName("GitHub's rate limit answers 403, and is not read as a token that stopped working")
    void aRateLimitIsNotARefusal() {
        rows.put(Setting.TICKET_PROVIDER.key(), TicketProvider.GITHUB.wireName());
        // The primary limit: the hour's calls spent.
        tracker.route("/repos/team/service/issues", Reply.status(403).with("x-ratelimit-remaining", "0"));
        assertThat(service.createForIssue(issue(), "team/service")).isEmpty();
        // A secondary limit: too many calls at once.
        tracker.route("/repos/team/service/issues", Reply.status(403).with("retry-after", "60"));
        assertThat(service.createForIssue(issue(), "team/service")).isEmpty();
        tracker.route("/repos/team/service/issues", Reply.status(429));
        assertThat(service.createForIssue(issue(), "team/service")).isEmpty();

        assertThat(service.tokenHealth().refused()).isEmpty();
        verify(settings, times(0)).replaceInternal(anyString(), anyString(), org.mockito.ArgumentMatchers.eq("refused"));

        // A 403 with calls left is the token lacking the permission: still a refusal.
        tracker.route("/repos/team/service/issues", Reply.status(403).with("x-ratelimit-remaining", "4999"));
        assertThat(service.createForIssue(issue(), "team/service")).isEmpty();
        assertThat(service.tokenHealth().refused()).hasValueSatisfying(refusal -> assertThat(refusal.status()).isEqualTo(403));
    }

    @Test
    @DisplayName("a refusal met by the daily check is recorded as one met by the sweep")
    void theCheckMeetsARefusalToo() {
        tracker.route(SELF, Reply.status(401));

        assertThat(service.checkTokenNow().refused()).hasValueSatisfying(refusal -> assertThat(refusal.status()).isEqualTo(401));
    }

    @Test
    @DisplayName("Jira says nothing of its tokens: the declared date is announced, and the tracker is not asked")
    void jiraUsesTheDeclaredDate() {
        rows.put(Setting.TICKET_PROVIDER.key(), TicketProvider.JIRA.wireName());
        rows.put(Setting.TICKET_PROJECT.key(), "SEC");

        TrackerTokenState.Health unknown = service.checkTokenNow();
        assertThat(unknown.expirySource()).isEqualTo(ExpirySource.UNKNOWN);
        assertThat(unknown.expiresAt()).isEmpty();

        rows.put(Setting.TICKET_TOKEN_EXPIRES_ON.key(), "2026-10-20");
        service.checkTokenIfDue();

        assertThat(service.tokenHealth().expirySource()).isEqualTo(ExpirySource.DECLARED);
        assertThat(rows).containsEntry(TrackerTokenState.ANNOUNCED, "expires_soon");
        assertThat(tracker.seen).isEmpty();
    }

    @Test
    @DisplayName("a new token forgets what was known of the previous one")
    void aNewTokenStartsAfresh() {
        tracker.route(SELF, Reply.status(401));
        service.checkTokenNow();
        assertThat(service.tokenHealth().refused()).isPresent();

        service.setToken("glpat-new");

        assertThat(service.tokenHealth().refused()).isEmpty();
        assertThat(service.tokenHealth().checkedAt()).isEmpty();
    }

    @Test
    @DisplayName("a refused token replaced by one that works is said to work again, once — the end of the alert")
    void aReplacedTokenIsSaidToWorkAgain() {
        tracker.route(SELF, Reply.status(401));
        service.checkTokenNow();

        service.setToken("glpat-replacement");
        tracker.route(SELF, Reply.json("{\"active\":true,\"expires_at\":\"2027-06-30\"}"));
        service.checkTokenNow();
        clock.advance(Duration.ofDays(1));
        service.checkTokenIfDue();

        assertThat(published).extracting(TokenAlert::notice).containsExactly(Notice.REFUSED, Notice.NONE);
        assertThat(published.getLast().previous()).isEqualTo(Notice.REFUSED);
        assertThat(published.getLast().operation())
                .isEqualTo(com.asmolabs.vectispire.common.domain.audit.AuditOperation.INTEGRATION_TOKEN_RESTORED);
    }

    @Test
    @DisplayName("a removed token says nothing: it neither expires nor works again")
    void aRemovedTokenSaysNothing() {
        tracker.route(SELF, Reply.status(401));
        service.checkTokenNow();

        service.setToken("");
        service.checkTokenNow();
        clock.advance(Duration.ofDays(2));
        service.checkTokenIfDue();

        assertThat(published).extracting(TokenAlert::notice).containsExactly(Notice.REFUSED);
    }

    @Test
    @DisplayName("of two instances noticing the same change, the one whose conditional update lost says nothing")
    void theInstanceThatLostSaysNothing() {
        tracker.route(SELF, Reply.status(401));
        anotherInstanceFirst.set(true);

        service.checkTokenNow();
        clock.advance(Duration.ofHours(1));
        service.checkTokenIfDue();

        assertThat(published).isEmpty();
        assertThat(rows).containsEntry(TrackerTokenState.ANNOUNCED, "refused");
    }

    @Test
    @DisplayName("no alert carries the token, nor the header it is sent in")
    void noAlertCarriesTheToken() {
        tracker.route(SELF, Reply.status(401));
        service.checkTokenNow();
        service.setToken("glpat-replacement");
        tracker.route(SELF, Reply.json("{\"active\":true,\"expires_at\":\"2026-10-15\"}"));
        service.checkTokenNow();

        assertThat(published).hasSize(2).allSatisfy(alert -> {
            String said = alert.sentence() + alert.headline() + alert.where() + alert.name() + alert.reference();
            assertThat(said).doesNotContain("glpat").doesNotContainIgnoringCase("private-token")
                    .doesNotContain(rows.get(Setting.TICKET_TOKEN.key()));
            assertThat(said).as("nor the tracker's address, a secret setting")
                    .doesNotContain(tracker.baseUrl()).doesNotContain(java.net.URI.create(tracker.baseUrl()).getAuthority());
        });
    }

    private static TicketableIssue issue() {
        return new TicketableIssue(
                1L, FindingType.VULNERABILITY, "CVE-2026-1", Severity.CRITICAL, "openssl", "3.5.1", "3.5.2",
                FixState.FIXED, Directness.DIRECT, null, null, true, 0.42, null, "A buffer overflow.", "abc");
    }

    /** A clock the test moves: the day between two checks is the point. */
    private static final class MovableClock extends Clock {

        private Instant now;

        MovableClock(Instant now) {
            this.now = now;
        }

        void advance(Duration by) {
            now = now.plus(by);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }
}
