package com.asmolabs.vectispire.core.forges;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.notifications.TokenAlert;
import com.asmolabs.vectispire.common.domain.notifications.TokenAlert.Notice;
import com.asmolabs.vectispire.common.domain.siem.SecurityEventType;
import com.asmolabs.vectispire.core.forges.persistence.ForgeConnectionEntity;
import com.asmolabs.vectispire.core.forges.persistence.ForgeConnectionRepository;
import com.asmolabs.vectispire.core.settings.SettingsService;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.transaction.support.TransactionOperations;

/**
 * Each forge connection's token expiry, announced once per change of what there is to say.
 *
 * <p><b>Why.</b> The expiry the forge reported was shown on the connections' list and nowhere else; a lapsed token
 * left every discovery and change-review reading of its connection failing until somebody opened it. The settings
 * are a map here, so that what is stored — and so what a restart would read — can be looked at; the database's half
 * of the conditional update is {@code TokenAlertsRoutesTest}'s.
 */
@DisplayName("a forge connection's token expiry")
class ForgeTokenWatchTest {

    private static final Instant START = Instant.parse("2026-10-13T08:00:00Z");

    private final Map<String, String> rows = new ConcurrentHashMap<>();
    private final List<TokenAlert> published = new ArrayList<>();
    private final AtomicBoolean anotherInstanceFirst = new AtomicBoolean();
    private final List<ForgeConnectionEntity> stored = new ArrayList<>();
    private ForgeConnectionRepository connections;
    private SettingsService settings;
    private MovableClock clock;
    private ForgeTokenWatch watch;
    private ForgeConnectionEntity connection;

    @BeforeEach
    void wire() {
        connections = mock(ForgeConnectionRepository.class);
        when(connections.findAllByOrderByNameAsc()).thenAnswer(call -> List.copyOf(stored));
        settings = mock(SettingsService.class);
        when(settings.internalValue(anyString())).thenAnswer(call -> Optional.ofNullable(rows.get(call.<String>getArgument(0))));
        when(settings.storeInternalIfAbsent(anyString(), anyString()))
                .thenAnswer(call -> rows.putIfAbsent(call.getArgument(0), call.getArgument(1)) == null);
        when(settings.replaceInternal(anyString(), anyString(), anyString())).thenAnswer(call -> {
            if (anotherInstanceFirst.getAndSet(false)) {
                rows.put(call.getArgument(0), call.getArgument(2));
                return false;
            }
            return rows.replace(call.getArgument(0), call.getArgument(1), call.getArgument(2));
        });
        doAnswer(call -> rows.remove(call.<String>getArgument(0))).when(settings).removeInternal(anyString());
        clock = new MovableClock(START);
        watch = newInstance();

        connection = connection("Platform GitLab", START.plus(Duration.ofDays(20)));
        stored.add(connection);
    }

    @Test
    @DisplayName("fourteen days ahead it is announced once, not every hour, and not again after a restart")
    void expiresSoonOnce() {
        watch.watch();
        assertThat(published).as("twenty days ahead: nothing to say yet").isEmpty();

        clock.advance(Duration.ofDays(7));
        watch.watch();
        clock.advance(Duration.ofHours(1));
        watch.watch();
        // A restart: a new instance of the watch, nothing in memory, the stored record read again.
        newInstance().watch();

        assertThat(published).singleElement().satisfies(alert -> {
            assertThat(alert.credential()).isEqualTo(TokenAlert.Credential.FORGE_CONNECTION);
            assertThat(alert.notice()).isEqualTo(Notice.EXPIRES_SOON);
            assertThat(alert.previous()).isEqualTo(Notice.NONE);
            assertThat(alert.reference()).isEqualTo(connection.getId().toString());
            assertThat(alert.expiresAt()).isEqualTo(START.plus(Duration.ofDays(20)));
            assertThat(alert.operation()).isEqualTo(AuditOperation.INTEGRATION_TOKEN_EXPIRING);
            assertThat(alert.signal()).isEqualTo(SecurityEventType.INTEGRATION_TOKEN_EXPIRING);
        });
        assertThat(rows).containsEntry(ForgeTokenWatch.ANNOUNCED + connection.getId(), "expires_soon");
    }

    @Test
    @DisplayName("past the expiry it is said to have stopped working, once")
    void expiredOnce() {
        clock.advance(Duration.ofDays(7));
        watch.watch();
        clock.advance(Duration.ofDays(14));
        watch.watch();
        clock.advance(Duration.ofHours(1));
        watch.watch();

        assertThat(published).extracting(TokenAlert::notice).containsExactly(Notice.EXPIRES_SOON, Notice.EXPIRED);
        assertThat(published.getLast().previous()).isEqualTo(Notice.EXPIRES_SOON);
        assertThat(published.getLast().signal()).isEqualTo(SecurityEventType.INTEGRATION_TOKEN_STOPPED);
    }

    @Test
    @DisplayName("a token replaced after it expired is said to work again, once")
    void replacedAfterExpiry() {
        clock.advance(Duration.ofDays(21));
        watch.watch();
        // The administrator replaced the token: the probe stored the new token's expiry.
        connection.setTokenExpiresAt(clock.instant().plus(Duration.ofDays(365)));
        watch.watch();
        watch.watch();

        assertThat(published).extracting(TokenAlert::notice).containsExactly(Notice.EXPIRED, Notice.NONE);
        assertThat(published.getLast().previous()).isEqualTo(Notice.EXPIRED);
        assertThat(published.getLast().operation()).isEqualTo(AuditOperation.INTEGRATION_TOKEN_RESTORED);
        assertThat(published.getLast().sentence()).endsWith("works again.");
    }

    @Test
    @DisplayName("a token whose expiry nobody knows is never announced")
    void anUnknownExpiryIsNotAnnounced() {
        connection.setTokenExpiresAt(null);
        clock.advance(Duration.ofDays(400));
        watch.watch();

        assertThat(published).isEmpty();
    }

    @Test
    @DisplayName("the alert names the connection and its server, never its token")
    void theConnectionIsNamedAndTheTokenIsNot() {
        clock.advance(Duration.ofDays(21));
        watch.watch();

        assertThat(published).singleElement().satisfies(alert -> {
            assertThat(alert.name()).isEqualTo("Platform GitLab");
            assertThat(alert.where()).isEqualTo("GitLab self-managed or Dedicated at https://gitlab.example.com");
            assertThat(alert.sentence()).contains("\"Platform GitLab\"").contains("https://gitlab.example.com");
            String said = alert.sentence() + alert.headline() + alert.where() + alert.name() + alert.reference();
            assertThat(said).doesNotContain(connection.getToken()).doesNotContain("glpat");
        });
    }

    @Test
    @DisplayName("of two instances noticing the same change, the one whose conditional update lost says nothing")
    void theInstanceThatLostSaysNothing() {
        clock.advance(Duration.ofDays(21));
        anotherInstanceFirst.set(true);
        watch.watch();
        watch.watch();

        assertThat(published).isEmpty();
        assertThat(rows).containsEntry(ForgeTokenWatch.ANNOUNCED + connection.getId(), "expired");
    }

    @Test
    @DisplayName("each connection is watched on its own: one that fails does not hold the others back")
    void oneFailureStopsNothingElse() {
        ForgeConnectionEntity broken = connection("Broken", START.minus(Duration.ofDays(1)));
        broken.setEdition("not-an-edition");
        stored.addFirst(broken);
        clock.advance(Duration.ofDays(21));

        watch.watch();

        assertThat(published).extracting(TokenAlert::name).containsExactly("Platform GitLab");
    }

    @Test
    @DisplayName("a deleted connection's record goes with it")
    void forgetRemovesTheRecord() {
        clock.advance(Duration.ofDays(21));
        watch.watch();

        watch.forget(connection.getId());

        assertThat(rows).doesNotContainKey(ForgeTokenWatch.ANNOUNCED + connection.getId());
    }

    private ForgeTokenWatch newInstance() {
        return new ForgeTokenWatch(connections, settings, event -> published.add((TokenAlert) event), clock,
                TransactionOperations.withoutTransaction());
    }

    private static ForgeConnectionEntity connection(String name, Instant expiresAt) {
        ForgeConnectionEntity entity = new ForgeConnectionEntity();
        entity.setId(UUID.randomUUID());
        entity.setName(name);
        entity.setKind("gitlab");
        entity.setEdition("gitlab_self_managed");
        entity.setBaseUrl("https://gitlab.example.com");
        entity.setToken("v2:Y2lwaGVydGV4dC1vZi10aGUtdG9rZW4=");
        entity.setCredentialKind("gitlab_bot");
        entity.setTokenExpiresAt(expiresAt);
        return entity;
    }

    /** A clock the test moves. */
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
