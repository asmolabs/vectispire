package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import com.asmolabs.vectispire.common.domain.crypto.PasswordHasher;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.persistence.UserEntity;
import com.asmolabs.vectispire.core.repositories.Users;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Clock;
import java.time.Instant;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;

/**
 * The second factor, over HTTP, as an anonymous caller.
 *
 * <p><b>Why this suite exists.</b> The MFA exchange had no route test at all, and two defects
 * lived in that gap: the chain refused {@code /auth/mfa/verify} outright — locking out every
 * account that had enabled MFA — and the handler counted no attempts, so the six-digit code
 * faced an unlimited number of tries inside a five-minute window. Neither is visible from a
 * unit test of the handler, because both are properties of the request rather than of the
 * method: one belongs to the filter chain, the other to what the second request is allowed to
 * do after the first.
 *
 * <p>The account here has {@code mfaEnabled} and no TOTP secret, so every code is wrong. That
 * is the point: what is under test is the refusal path, and a wrong code is the only input it
 * needs.
 */
@DisplayName("MFA verification")
class MfaVerificationRoutesTest extends ApiTestBase {

    private static final String PASSWORD = "correct horse battery staple";

    @Autowired
    private Users userStore;

    @Autowired
    private Clock testClock;

    private String createMfaUser() {
        Instant now = testClock.instant();
        UserEntity user = new UserEntity();
        user.setUsername("mfa-" + System.nanoTime());
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
                        .content(write(new AuthController.LoginRequest(username, PASSWORD, null))))
                .andReturn();

        assertThat(result.getResponse().getStatus())
                .as("the password step must succeed before there is anything to verify")
                .isEqualTo(200);

        JsonNode body = json.readTree(result.getResponse().getContentAsString());
        assertThat(body.get("mfa_required").asBoolean())
                .as("an account with MFA enabled must be challenged, not signed in")
                .isTrue();
        assertThat(body.get("token").isNull())
                .as("no session may be issued before the second factor")
                .isTrue();

        return body.get("mfa_token").asText();
    }

    private MvcResult attempt(String mfaToken, String code) throws Exception {
        return mvc.perform(post("/api/v1/auth/mfa/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(new AuthController.MfaVerifyRequest(mfaToken, code))))
                .andReturn();
    }

    @Test
    @DisplayName("is reachable without a bearer token, because it is what issues one")
    void isReachableAnonymously() throws Exception {
        String mfaToken = signInAndGetChallenge(createMfaUser());

        MvcResult result = attempt(mfaToken, "000000");

        // 401 is the right answer to a wrong code. What must not happen is a 401 produced by the
        // filter chain before the handler runs, which is what locked MFA accounts out: the
        // handler answering at all is the property under test.
        assertThat(result.getHandler())
                .as("the filter chain must let an anonymous MFA verification through")
                .isNotNull();
        assertThat(result.getResponse().getStatus()).isEqualTo(401);
    }

    @Test
    @DisplayName("destroys the challenge after three wrong codes, so a fourth has nothing to guess against")
    void exhaustedChallengeIsDestroyed() throws Exception {
        String mfaToken = signInAndGetChallenge(createMfaUser());

        // The first two are ordinary refusals: the challenge is still alive.
        for (int attempt = 1; attempt <= 2; attempt++) {
            MvcResult result = attempt(mfaToken, "00000" + attempt);
            assertThat(result.getResponse().getStatus()).isEqualTo(401);
            assertThat(result.getResponse().getErrorMessage())
                    .as("attempt %d must still be answered as a wrong code", attempt)
                    .contains("Invalid verification code");
        }

        // The third exhausts it. The message is deliberately the same — telling the caller how
        // many tries are left is telling an attacker.
        MvcResult third = attempt(mfaToken, "000003");
        assertThat(third.getResponse().getStatus()).isEqualTo(401);
        assertThat(third.getResponse().getErrorMessage()).contains("Invalid verification code");

        // The fourth finds no challenge at all: the token is spent, and the only way forward is
        // the password step again.
        MvcResult fourth = attempt(mfaToken, "000004");
        assertThat(fourth.getResponse().getStatus()).isEqualTo(401);
        assertThat(fourth.getResponse().getErrorMessage())
                .as("the challenge must be gone, not merely refusing codes")
                .contains("expired or is invalid");
    }

    @Test
    @DisplayName("a spent challenge cannot be revived by a second sign-in's token")
    void eachSignInGetsItsOwnChallenge() throws Exception {
        String username = createMfaUser();
        String first = signInAndGetChallenge(username);

        for (int attempt = 1; attempt <= 3; attempt++) {
            attempt(first, "00000" + attempt);
        }

        // A fresh password step issues a new challenge, and it starts with its full allowance:
        // burning one must not burn the account.
        String second = signInAndGetChallenge(username);
        assertThat(second).isNotEqualTo(first);

        MvcResult result = attempt(second, "111111");
        assertThat(result.getResponse().getStatus()).isEqualTo(401);
        assertThat(result.getResponse().getErrorMessage())
                .as("the new challenge must accept attempts, not inherit the old one's count")
                .contains("Invalid verification code");
    }
}
