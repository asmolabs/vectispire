package com.asmolabs.vectispire.common.domain.auth;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

@DisplayName("sessions")
class SessionsTest {

    private static final Instant NOW = Instant.parse("2026-08-10T08:00:00Z");
    private static final Sessions.Policy POLICY = Sessions.Policy.DEFAULT;

    @Test
    @DisplayName("a fresh session is active")
    void freshSessionIsActive() {
        assertThat(Sessions.stateOf(NOW, NOW, NOW, POLICY)).isEqualTo(Sessions.State.ACTIVE);
    }

    @Test
    @DisplayName("the absolute lifetime bounds what a stolen token allows")
    void absoluteLifetimeExpires() {
        Instant created = NOW.minus(POLICY.absoluteLifetime());

        // Busy the whole time, so only the absolute ceiling can be closing it.
        assertThat(Sessions.stateOf(created, NOW, NOW, POLICY)).isEqualTo(Sessions.State.EXPIRED);
    }

    @Test
    @DisplayName("silence closes a session that still has lifetime left")
    void idleLifetimeCloses() {
        assertThat(Sessions.stateOf(NOW.minus(Duration.ofHours(2)), NOW.minus(POLICY.idleLifetime()), NOW, POLICY))
                .isEqualTo(Sessions.State.IDLE);
    }

    @Test
    @DisplayName("the two causes of closure are told apart")
    void expiredAndIdleAreDistinct() {
        // The operator tuning the durations needs to know which one is actually closing their
        // users' sessions. One "closed" state would leave them guessing.
        assertThat(Sessions.State.values()).containsExactly(
                Sessions.State.ACTIVE, Sessions.State.EXPIRED, Sessions.State.IDLE);
    }

    @Test
    @DisplayName("a token is opaque, and never the same twice")
    void tokensAreOpaqueAndUnique() {
        String first = Sessions.issue().token();

        assertThat(first).hasSize(43).doesNotContain(".").isNotEqualTo(Sessions.issue().token());
    }

    @Test
    @DisplayName("a minted token comes with the hash that will be stored in its place")
    void mintingProducesBothForms() {
        Sessions.IssuedToken minted = Sessions.issue();

        // 64 hex characters against the token's 43: the two are not confusable by width either,
        // which is what makes a clear token left in the column visible rather than plausible.
        assertThat(minted.hash()).hasSize(64).isEqualTo(Sessions.hashOf(minted.token()));
        assertThat(minted.hash()).isNotEqualTo(minted.token());
    }

    @Test
    @DisplayName("the hash is a verifier: it does not hash to itself")
    void theHashIsNotACredential() {
        Sessions.IssuedToken minted = Sessions.issue();

        // Presenting the stored value looks up the hash *of the stored value*, which is not a
        // key of the table. Reading the session store therefore authenticates nobody — the
        // property the whole change exists for, stated where it can be checked without a
        // database.
        assertThat(Sessions.hashOf(minted.hash())).isNotEqualTo(minted.hash());
    }

    @Test
    @DisplayName("extracts a bearer token")
    void extractsBearerToken() {
        assertThat(Sessions.bearerToken("Bearer abc123")).contains("abc123");
    }

    @ParameterizedTest(name = "refuses [{0}] without saying which kind of wrong it is")
    @ValueSource(strings = {"", "   ", "abc123", "bearer abc123", "Bearer ", "Bearer a b", "Basic abc123"})
    void refusesAnythingElse(String header) {
        // Telling "absent", "malformed" and "unknown" apart would inform somebody probing
        // without helping anybody else.
        assertThat(Sessions.bearerToken(header)).isEmpty();
    }

    @Test
    @DisplayName("a null header is not a token")
    void refusesNull() {
        assertThat(Sessions.bearerToken(null)).isEmpty();
    }

    @Test
    @DisplayName("activity is written down at a grain, and never late enough to keep a dead session alive")
    void activityIsRecordedAtAGrain() {
        Sessions.Policy policy = Sessions.Policy.DEFAULT;   // inactivité : soixante minutes
        Instant seen = Instant.parse("2026-09-04T10:00:00Z");

        // The saving: a screen's second request does not rewrite the row the first has just
        // written. That is the whole point of the throttle — three parallel calls fought over one
        // row, and on the single-file engine they blocked one another.
        assertThat(Sessions.shouldRecordActivity(seen, seen.plusMillis(40), policy)).isFalse();
        assertThat(Sessions.shouldRecordActivity(seen, seen.plusSeconds(59), policy)).isFalse();
        assertThat(Sessions.shouldRecordActivity(seen, seen.plusSeconds(60), policy)).isTrue();

        // **And the guarantee that the saving costs nothing.** What is skipped is a write, not a
        // close: a session whose activity went unrecorded looks older than it is, so it expires
        // possibly early and never late. This is the case that matters — at the window's edge,
        // activity is always recorded, so a user who is present is never signed out because we
        // stopped listening.
        Instant edge = seen.plus(policy.idleLifetime()).minusSeconds(1);
        assertThat(Sessions.shouldRecordActivity(seen, edge, policy)).isTrue();
        assertThat(Sessions.isActive(seen, seen, edge, policy)).isTrue();

        // A very short window is not throttled finer than a second: the grain would be zero, and
        // `!now.isBefore(lastSeenAt)` would be permanently true — the throttle would vanish with
        // nothing saying so.
        Sessions.Policy strict = new Sessions.Policy(Duration.ofHours(1), Duration.ofSeconds(30));
        assertThat(Sessions.shouldRecordActivity(seen, seen.plusMillis(500), strict)).isFalse();
        assertThat(Sessions.shouldRecordActivity(seen, seen.plusSeconds(1), strict)).isTrue();
    }
}
