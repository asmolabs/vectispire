package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import com.asmolabs.vectispire.common.domain.auth.Sessions;
import com.asmolabs.vectispire.common.domain.crypto.PasswordHasher;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.access.persistence.MfaChallengeEntity;
import com.asmolabs.vectispire.core.access.persistence.MfaChallenges;
import com.asmolabs.vectispire.core.access.persistence.UserEntity;
import com.asmolabs.vectispire.core.access.persistence.Users;
import com.asmolabs.vectispire.core.access.web.AuthController;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Clock;
import java.time.Instant;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.server.ResponseStatusException;

/**
 * A challenge issued by one control plane is answered by another.
 *
 * <p><b>Why this exists.</b> The challenge lived in a map on {@code AuthController}, so it lived
 * in one process. Running two instances is documented and supported — a whole section of
 * {@code 04-runtime-and-deployment} is about it — and multi-factor sign-in was the one feature
 * that silently did not survive it: the password is exchanged on instance A, the browser's next
 * request lands on B, and B has never heard of the token. The user is told the challenge has
 * expired, one second after it was created, and nothing distinguishes that in a log from a real
 * five-minute timeout.
 *
 * <p><b>How "another instance" is modelled.</b> A second {@link AuthController}, built here from
 * the same beans. That is a direct call, which {@link ApiTestBase} argues against for routes —
 * rightly, since a direct call cannot see a path or an authorization annotation. Here it is the
 * point: what is under test is whether the state a request left behind is reachable from an
 * object that shares nothing with the first but the database, which is exactly what a second
 * JVM behind a load balancer is.
 */
@DisplayName("an MFA challenge")
class MfaChallengeIsSharedTest extends ApiTestBase {

    private static final String PASSWORD = "correct horse battery staple";

    @Autowired
    private Users userStore;

    @Autowired
    private MfaChallenges challenges;

    @Autowired
    private Clock testClock;

    @Autowired
    private org.springframework.context.ApplicationContext context;

    @Test
    @DisplayName("is verifiable by a second instance that never saw the sign-in")
    void is_verifiable_by_a_second_instance() throws Exception {
        String username = anMfaAccount();
        String mfaToken = signInAndGetChallenge(username);

        // The other control plane: a genuinely new AuthController, wired from the same beans.
        // `createBean` constructs one rather than handing back the singleton — asking the
        // context for the bean would test nothing, since it is the object that just answered.
        AuthController otherInstance =
                context.getAutowireCapableBeanFactory().createBean(AuthController.class);

        // The account has no TOTP secret, so no code can be right — and that is what makes the
        // assertion sharp. A challenge the second instance cannot find is refused as "expired or
        // invalid"; one it can find is refused as an invalid code. The two messages are exactly
        // what tells the two designs apart.
        ResponseStatusException refusal = org.assertj.core.api.Assertions.catchThrowableOfType(
                ResponseStatusException.class,
                () -> otherInstance.verifyMfa(new AuthController.MfaVerifyRequest(mfaToken, "000000"), request()));

        assertThat(refusal.getReason())
                .as("the second instance must recognise the challenge rather than report it expired")
                .isEqualTo("Invalid verification code.");
    }

    @Test
    @DisplayName("is stored as a hash, never as the token that was handed out")
    void is_stored_as_a_hash() throws Exception {
        String mfaToken = signInAndGetChallenge(anMfaAccount());

        assertThat(challenges.findById(mfaToken))
                .as("the token itself must not be a key: the table would then hold live credentials")
                .isEmpty();

        MfaChallengeEntity stored = challenges
                .findById(Sessions.hashOf(mfaToken))
                .orElseThrow(() -> new AssertionError("the challenge was not persisted at all"));

        assertThat(stored.getTokenHash()).isNotEqualTo(mfaToken);
        assertThat(stored.getAttempts()).isZero();
        assertThat(stored.getExpiresAt()).isAfter(testClock.instant());
    }

    @Test
    @DisplayName("is removed from the shared store once it has been used up")
    void is_removed_once_used_up() throws Exception {
        String mfaToken = signInAndGetChallenge(anMfaAccount());
        String key = Sessions.hashOf(mfaToken);

        for (int attempt = 0; attempt < 3; attempt++) {
            mvc.perform(post("/api/v1/auth/mfa/verify")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(write(new AuthController.MfaVerifyRequest(mfaToken, "000000"))))
                    .andReturn();
        }

        assertThat(challenges.findById(key))
                .as("a destroyed challenge must be gone for every instance, not just this one")
                .isEmpty();
    }

    private jakarta.servlet.http.HttpServletRequest request() {
        org.springframework.mock.web.MockHttpServletRequest request =
                new org.springframework.mock.web.MockHttpServletRequest();
        request.setRemoteAddr("203.0.113.7");
        return request;
    }

    private String anMfaAccount() {
        Instant now = testClock.instant();
        UserEntity user = new UserEntity();
        user.setUsername("mfa-shared-" + System.nanoTime());
        user.setPassword(PasswordHasher.hash(PASSWORD));
        user.setRole(Role.USER.name());
        user.setIsActive(true);
        user.setMustChangePassword(false);
        user.setMfaEnabled(true);
        user.setCreatedAt(now);
        user.setUpdatedAt(now);
        return userStore.save(user).getUsername();
    }

    private String signInAndGetChallenge(String username) throws Exception {
        MvcResult result = mvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(new AuthController.LoginRequest(username, PASSWORD))))
                .andReturn();

        JsonNode body = json.readTree(result.getResponse().getContentAsString());
        assertThat(body.get("mfa_required").asBoolean()).isTrue();
        return body.get("mfa_token").asText();
    }
}
