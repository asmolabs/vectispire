package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.auth.LoginThrottle;
import com.asmolabs.vectispire.common.domain.crypto.DerivationGate;
import com.asmolabs.vectispire.common.domain.crypto.PasswordHasher;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.access.web.AuthController;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;

/**
 * Sign-in while every password derivation permit is taken.
 *
 * <p>Each admitted attempt runs one Argon2id derivation of 19 MiB, a name nobody holds included, and
 * the throttles bound each client rather than all of them together. The bound is {@code DerivationGate};
 * here it is one permit, held by a derivation that does not finish until the test lets it, so the
 * saturation is a fact rather than a race.
 */
@DisplayName("sign-in when password derivations are saturated")
class PasswordDerivationSaturationRoutesTest extends ApiTestBase {

    private static final String PASSWORD = "correct horse battery staple";

    private String username;
    private String session;
    private DerivationGate shipped;
    private DerivationGate gate;
    private CountDownLatch release;
    private CompletableFuture<Object> holder;

    @BeforeEach
    void saturate() throws Exception {
        // Before the gate is closed: creating the account derives its hash too.
        username = "saturated-" + System.nanoTime();
        session = tokenFor(username, Role.USER, false);

        shipped = PasswordHasher.gate();
        gate = new DerivationGate(1, Duration.ofMillis(100));
        PasswordHasher.bound(gate);
        release = new CountDownLatch(1);
        CountDownLatch holding = new CountDownLatch(1);
        holder = CompletableFuture.supplyAsync(() -> gate.run(() -> {
            holding.countDown();
            try {
                release.await(30, TimeUnit.SECONDS);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
            }
            return null;
        }));
        assertThat(holding.await(10, TimeUnit.SECONDS)).isTrue();
    }

    @AfterEach
    void restore() throws Exception {
        release.countDown();
        holder.get(10, TimeUnit.SECONDS);
        PasswordHasher.bound(shipped);
    }

    private MvcResult signIn(String username, String password) throws Exception {
        return mvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(new AuthController.LoginRequest(username, password))))
                .andReturn();
    }

    @Test
    @DisplayName("is answered 503 with Retry-After, in the same words for an account and for a name nobody holds")
    void busyIsAnsweredAlike() throws Exception {
        MvcResult existing = mvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(new AuthController.LoginRequest(username, PASSWORD))))
                .andExpect(status().isServiceUnavailable())
                .andExpect(header().string("Retry-After", "1"))
                .andExpect(jsonPath("$.code").value("unavailable"))
                .andExpect(jsonPath("$.retryAfterSeconds").value(1))
                .andReturn();
        MvcResult unknown = signIn("nobody-" + System.nanoTime(), PASSWORD);

        assertThat(unknown.getResponse().getStatus()).isEqualTo(503);
        assertThat(unknown.getResponse().getHeader("Retry-After")).isEqualTo("1");
        assertThat(detailOf(unknown)).isEqualTo(detailOf(existing));
        // The permit given back by every refused attempt, and the holder's still held.
        assertThat(gate.available()).isZero();
    }

    /**
     * Counted, a person retrying through a saturated minute would spend their own budget on attempts
     * whose password was never compared, and be locked out for a quarter of an hour once it cleared.
     */
    @Test
    @DisplayName("a refusal for saturation spends none of the account's budget")
    void busyIsNotAFailure() throws Exception {
        for (int attempt = 0; attempt <= LoginThrottle.MAX_ATTEMPTS_PER_USER; attempt++) {
            assertThat(signIn(username, PASSWORD).getResponse().getStatus()).isEqualTo(503);
        }

        release.countDown();
        holder.get(10, TimeUnit.SECONDS);

        assertThat(signIn(username, PASSWORD).getResponse().getStatus()).isEqualTo(200);
    }

    @Test
    @DisplayName("a signed-in password check is refused the same way, and spends nothing either")
    void aPasswordChangeIsBusyToo() throws Exception {
        String wrong = write(Map.of("current_password", "not it", "new_password", "a brand new passphrase"));

        for (int attempt = 0; attempt <= LoginThrottle.MAX_ATTEMPTS_PER_USER; attempt++) {
            mvc.perform(authenticated(post("/api/v1/auth/change-password"), session)
                            .contentType(MediaType.APPLICATION_JSON).content(wrong))
                    .andExpect(status().isServiceUnavailable())
                    .andExpect(header().exists("Retry-After"));
        }

        release.countDown();
        holder.get(10, TimeUnit.SECONDS);

        assertThat(signIn(username, PASSWORD).getResponse().getStatus()).isEqualTo(200);
    }
}
