package com.asmolabs.vectispire.common.domain.auth;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.stream.IntStream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("login throttling")
class LoginThrottleTest {

    private static final Instant NOW = Instant.parse("2026-08-10T08:00:00Z");

    private static List<Instant> attempts(int count, Instant at) {
        return IntStream.range(0, count).mapToObj(i -> at).toList();
    }

    @Test
    @DisplayName("lets an attempt through below both thresholds")
    void allowsBelowBothThresholds() {
        LoginThrottle.Decision decision = LoginThrottle.decide(
                new LoginThrottle.Attempts(attempts(4, NOW), attempts(19, NOW)), NOW);

        assertThat(decision).isEqualTo(new LoginThrottle.Decision(true, Duration.ZERO));
    }

    @Test
    @DisplayName("blocks at the user threshold, so a spread-out attacker gains nothing")
    void blocksAtTheUserThreshold() {
        // Without this counter an attacker spread across several machines would try as many
        // passwords as they liked against one account.
        LoginThrottle.Decision decision = LoginThrottle.decide(
                new LoginThrottle.Attempts(attempts(LoginThrottle.MAX_ATTEMPTS_PER_USER, NOW), List.of()), NOW);

        assertThat(decision.allowed()).isFalse();
        assertThat(decision.retryAfter()).isEqualTo(LoginThrottle.WINDOW);
    }

    @Test
    @DisplayName("blocks at the client threshold, so one machine cannot sweep the user list")
    void blocksAtTheClientThreshold() {
        assertThat(LoginThrottle.decide(
                        new LoginThrottle.Attempts(List.of(), attempts(LoginThrottle.MAX_ATTEMPTS_PER_CLIENT, NOW)), NOW)
                .allowed())
                .isFalse();
    }

    @Test
    @DisplayName("allows a shared workstation more room than an account")
    void clientThresholdIsHigher() {
        // A shared workstation can legitimately watch several people mistype; an account
        // cannot. Equal thresholds would either lock the workstation or unlock the account.
        assertThat(LoginThrottle.MAX_ATTEMPTS_PER_CLIENT).isGreaterThan(LoginThrottle.MAX_ATTEMPTS_PER_USER);
    }

    @Test
    @DisplayName("announces the delay of the most constraining counter")
    void announcesTheLongestWait() {
        LoginThrottle.Decision decision = LoginThrottle.decide(
                new LoginThrottle.Attempts(
                        attempts(LoginThrottle.MAX_ATTEMPTS_PER_USER, NOW.minusSeconds(60)),
                        attempts(LoginThrottle.MAX_ATTEMPTS_PER_CLIENT, NOW)),
                NOW);

        assertThat(decision.retryAfter()).isEqualTo(LoginThrottle.WINDOW);
    }

    @Test
    @DisplayName("forgets attempts that have left the window")
    void forgetsOldAttempts() {
        List<Instant> old = attempts(LoginThrottle.MAX_ATTEMPTS_PER_USER, NOW.minus(LoginThrottle.WINDOW).minusMillis(1));

        assertThat(LoginThrottle.decide(new LoginThrottle.Attempts(old, List.of()), NOW).allowed()).isTrue();
    }

    @Test
    @DisplayName("releases gradually, with no free burst at a boundary")
    void windowSlides() {
        // A fixed window resets on the hour and hands an attacker a burst at the boundary.
        List<Instant> staggered = List.of(
                NOW.minus(LoginThrottle.WINDOW).minusMillis(1),
                NOW.minusSeconds(10),
                NOW.minusSeconds(9),
                NOW.minusSeconds(8),
                NOW.minusSeconds(7));

        assertThat(LoginThrottle.decide(new LoginThrottle.Attempts(staggered, List.of()), NOW).allowed()).isTrue();
    }

    @Test
    @DisplayName("computes the delay from the oldest failure still counted")
    void delayFollowsTheOldestAttempt() {
        Instant at = NOW.minus(LoginThrottle.WINDOW).plusSeconds(30);

        assertThat(LoginThrottle.decide(
                        new LoginThrottle.Attempts(attempts(LoginThrottle.MAX_ATTEMPTS_PER_USER, at), List.of()), NOW)
                .retryAfter())
                .isEqualTo(Duration.ofSeconds(30));
    }

    @Test
    @DisplayName("never announces zero to a caller that is still blocked")
    void neverAnnouncesZeroWhenBlocked() {
        // Announcing zero makes the caller retry immediately and fail again — the throttle
        // telling a lie about itself.
        Instant at = NOW.minus(LoginThrottle.WINDOW).plusMillis(100);
        LoginThrottle.Decision decision = LoginThrottle.decide(
                new LoginThrottle.Attempts(attempts(LoginThrottle.MAX_ATTEMPTS_PER_USER, at), List.of()), NOW);

        assertThat(decision.allowed()).isFalse();
        assertThat(decision.retryAfter()).isGreaterThan(Duration.ZERO);
    }

    @Test
    @DisplayName("the user key is normalized, so varying the case does not triple the budget")
    void userKeyIsNormalized() {
        assertThat(LoginThrottle.userKey("  Alice  ")).isEqualTo(LoginThrottle.userKey("alice"));
        assertThat(LoginThrottle.userKey("ALICE")).isEqualTo("login:user:alice");
    }

    @Test
    @DisplayName("the two namespaces stay apart")
    void namespacesAreDistinct() {
        assertThat(LoginThrottle.userKey("x")).isNotEqualTo(LoginThrottle.clientKey("x"));
    }

    @Test
    @DisplayName("keeps only the attempts still inside the window")
    void filtersTheWindow() {
        List<Instant> kept = LoginThrottle.withinWindow(
                List.of(NOW.minus(LoginThrottle.WINDOW).minusMillis(1), NOW.minusSeconds(1), NOW), NOW);

        assertThat(kept).isEqualTo(List.of(NOW.minusSeconds(1), NOW));
        assertThat(LoginThrottle.withinWindow(Collections.emptyList(), NOW)).isEmpty();
    }
}
