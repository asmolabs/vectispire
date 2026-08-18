package com.asmolabs.zanshin.common.domain.auth;

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
        String first = Sessions.newToken();

        assertThat(first).hasSize(43).doesNotContain(".").isNotEqualTo(Sessions.newToken());
    }

    @Test
    @DisplayName("token comparison does not depend on how much of it was right")
    void tokensMatchConstantTime() {
        assertThat(Sessions.tokensMatch("abc", "abc")).isTrue();
        assertThat(Sessions.tokensMatch("abc", "abd")).isFalse();
        assertThat(Sessions.tokensMatch("abc", "abcd")).isFalse();
        assertThat(Sessions.tokensMatch(null, "abc")).isFalse();
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
}
