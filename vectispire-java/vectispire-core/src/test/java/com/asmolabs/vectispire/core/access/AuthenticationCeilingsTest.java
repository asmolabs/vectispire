package com.asmolabs.vectispire.core.access;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;

import com.asmolabs.vectispire.common.domain.auth.LoginThrottle;
import com.asmolabs.vectispire.common.domain.crypto.PasswordHasher;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.access.persistence.UserEntity;
import com.asmolabs.vectispire.core.access.persistence.UserRepository;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;

/**
 * The authentication ceilings hold when the attempts arrive together.
 *
 * <p><b>The defect.</b> Every ceiling was a check, then the verification, then a written failure.
 * Attempts sent at once all read the count before any of them wrote, and all were verified: a
 * ceiling of five wrong codes let through as many as the attacker sent in one burst. Each attempt
 * now writes its failure and commits before it counts — see {@code AuthService.Reservation}.
 *
 * <p><b>The interleaving is forced where it can be.</b> The second-factor cases hold every attempt
 * that reached the code check at a gate until every attempt has either reached it or been refused:
 * without the reservation, all of them read "under the ceiling" before any failure exists, which
 * is the worst interleaving and the one a burst produces. The password cases cannot be held at the
 * derivation, which is static; they rely on its cost instead — tens of milliseconds between the
 * count and the write, against a start gate that releases every attempt at once.
 */
@DisplayName("the authentication ceilings, under concurrent attempts")
class AuthenticationCeilingsTest extends VectispireContextTest {

    private static final String PASSWORD = "correct horse battery staple";
    private static final int BURST = 12;

    @Autowired
    private AuthService auth;

    @Autowired
    private AuthenticationFlowService flows;

    @Autowired
    private UserRepository users;

    @MockitoSpyBean
    private TotpService totp;

    private final ExecutorService pool = Executors.newFixedThreadPool(BURST);

    @AfterEach
    void stop() {
        pool.shutdownNow();
    }

    @Test
    @DisplayName("a burst of wrong passwords reaches the verification at most five times")
    void passwords() throws Exception {
        String name = account(false).username();

        List<AuthService.Outcome> outcomes = concurrently(index -> () -> auth.login(new AuthService.LoginRequest(
                name, "wrong-" + index, "probe", "198.51.100." + index)).outcome(), null);

        assertThat(outcomes).filteredOn(AuthService.Outcome.Invalid.class::isInstance)
                .hasSizeLessThanOrEqualTo(LoginThrottle.MAX_ATTEMPTS_PER_USER);
        assertThat(outcomes).allMatch(outcome -> outcome instanceof AuthService.Outcome.Invalid
                || outcome instanceof AuthService.Outcome.Blocked);
    }

    @Test
    @DisplayName("a burst of wrong current passwords on a session is checked at most five times")
    void passwordChanges() throws Exception {
        UserView account = account(false);

        List<AuthenticationFlowService.PasswordChange> outcomes = concurrently(index -> () -> flows.changePassword(
                account, Optional.empty(), "wrong-" + index, "a new password of some length", "198.51.100.1", "probe"),
                null);

        assertThat(outcomes).filteredOn(AuthenticationFlowService.PasswordChange.CurrentPasswordWrong.class::isInstance)
                .hasSizeLessThanOrEqualTo(LoginThrottle.MAX_ATTEMPTS_PER_USER);
        assertThat(outcomes).allMatch(outcome -> !(outcome instanceof AuthenticationFlowService.PasswordChange.Changed));
    }

    @Test
    @DisplayName("a burst of wrong codes across challenges reaches the code check at most five times")
    void secondFactorCodes() throws Exception {
        UserView account = account(true);
        // Four challenges, three presentations each: the challenge's own limit admits all twelve,
        // so only the account's budget can stop them.
        List<String> challenges = new ArrayList<>();
        for (int i = 0; i < 4; i++) {
            AuthenticationFlowService.SignIn signIn = flows.signIn(
                    new AuthenticationFlowService.Attempt(account.username(), PASSWORD, "probe", "198.51.100.1"));
            challenges.add(((AuthenticationFlowService.SignIn.ChallengeIssued) signIn).mfaToken());
        }
        CountDownLatch gate = gateTheCodeCheck();

        List<AuthenticationFlowService.Verification> outcomes = concurrently(
                index -> () -> flows.verify(challenges.get(index % 4), "00000" + (index % 10), "probe", "198.51.100.1"),
                gate);

        assertThat(outcomes).filteredOn(AuthenticationFlowService.Verification.WrongCode.class::isInstance)
                .hasSizeLessThanOrEqualTo(LoginThrottle.MAX_SECOND_FACTOR_FAILURES);
        assertThat(outcomes).noneMatch(AuthenticationFlowService.Verification.Verified.class::isInstance);
    }

    @Test
    @DisplayName("a burst of wrong codes to switch the factor off reaches the code check at most five times")
    void disablingTheFactor() throws Exception {
        UserView account = account(true);
        CountDownLatch gate = gateTheCodeCheck();

        List<String> outcomes = concurrently(index -> () -> {
            try {
                totp.disable(account, "00000" + (index % 10));
                return "disabled";
            } catch (TotpService.SecondFactorLockedException locked) {
                return "locked";
            } catch (IllegalArgumentException wrong) {
                return "wrong";
            }
        }, gate);

        assertThat(outcomes).filteredOn("wrong"::equals).hasSizeLessThanOrEqualTo(LoginThrottle.MAX_SECOND_FACTOR_FAILURES);
        assertThat(outcomes).doesNotContain("disabled");
    }

    /**
     * Holds each attempt that reaches the code check until every attempt of the burst has either
     * reached it or come back without it.
     */
    private CountDownLatch gateTheCodeCheck() throws Exception {
        CountDownLatch gate = new CountDownLatch(BURST);
        doAnswer(call -> {
            ENTERED.set(true);
            gate.countDown();
            assertThat(gate.await(30, TimeUnit.SECONDS)).as("the burst never assembled at the gate").isTrue();
            return call.callRealMethod();
        }).when(totp).verify(any(), any());
        return gate;
    }

    private static final ThreadLocal<Boolean> ENTERED = ThreadLocal.withInitial(() -> false);

    private interface Attempt<T> {
        Callable<T> at(int index);
    }

    /** Every attempt released at once; a gate, if any, is told of those that never reached it. */
    private <T> List<T> concurrently(Attempt<T> attempt, CountDownLatch gate) throws Exception {
        CountDownLatch start = new CountDownLatch(1);
        List<Future<T>> futures = new ArrayList<>();
        for (int index = 0; index < BURST; index++) {
            Callable<T> call = attempt.at(index);
            futures.add(pool.submit(() -> {
                start.await();
                try {
                    return call.call();
                } finally {
                    if (gate != null && !ENTERED.get()) {
                        gate.countDown();
                    }
                    ENTERED.remove();
                }
            }));
        }
        start.countDown();
        List<T> outcomes = new ArrayList<>();
        for (Future<T> future : futures) {
            outcomes.add(future.get(60, TimeUnit.SECONDS));
        }
        return outcomes;
    }

    private UserView account(boolean mfa) {
        Instant now = Instant.now();
        UserEntity user = new UserEntity();
        user.setUsername("burst-" + System.nanoTime());
        user.setPassword(PasswordHasher.hash(PASSWORD));
        user.setRole(Role.USER.name());
        user.setIsActive(true);
        user.setMustChangePassword(false);
        // Enabled with no secret and no backup codes: every code is wrong, which is all a
        // ceiling on wrong codes needs.
        user.setMfaEnabled(mfa);
        user.setCreatedAt(now);
        user.setUpdatedAt(now);
        return UserView.of(users.save(user));
    }
}
