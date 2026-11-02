package com.asmolabs.vectispire.core.api;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.auth.LoginThrottle;
import com.asmolabs.vectispire.common.domain.auth.Totp;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.access.persistence.LoginAttemptEntity;
import com.asmolabs.vectispire.core.access.persistence.LoginAttemptRepository;
import com.asmolabs.vectispire.core.access.persistence.UserRepository;
import java.time.Clock;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

/**
 * The account's sign-in budget across clients, as the sign-in screen meets it: a 429 with its own
 * code and {@code Retry-After}, and the second factor sent with the password as the way past it.
 */
@DisplayName("the account's sign-in budget across clients")
class AccountBudgetRoutesTest extends ApiTestBase {

    private static final String PASSWORD = "correct horse battery staple";

    @Autowired
    private LoginAttemptRepository attempts;

    @Autowired
    private UserRepository users;

    @Autowired
    private Clock clock;

    @Test
    @DisplayName("is answered 429 account-throttled with Retry-After, and the owner's second factor gets past it")
    void theSecondFactorGetsTheOwnerPastTheBudget() throws Exception {
        String username = "owner-" + System.nanoTime();
        String secret = enrolSecondFactor(tokenFor(username, Role.ADMIN, false));
        spendTheBudget(users.findByUsername(username).orElseThrow().getId());

        mvc.perform(signIn(username, PASSWORD, null))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().exists("Retry-After"))
                .andExpect(jsonPath("$.code").value("account-throttled"))
                .andExpect(jsonPath("$.retryAfterSeconds").isNumber());

        // A wrong code is the same refusal, as a wrong password with a right code is: past the budget
        // the answer says nothing about which of the two was wrong.
        // And at the same moment: a right password goes on to reserve, check and audit the code, which a
        // wrong one never does, so both wait out one deadline rather than answer as soon as they know.
        long rightPassword = System.nanoTime();
        mvc.perform(signIn(username, PASSWORD, "000000"))
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.code").value("account-throttled"));
        long wrongPassword = System.nanoTime();
        mvc.perform(signIn(username, "not the password", Totp.generateCode(secret, clock.instant().plusSeconds(30))))
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.code").value("account-throttled"));
        long done = System.nanoTime();
        org.assertj.core.api.Assertions.assertThat(java.time.Duration.ofNanos(wrongPassword - rightPassword))
                .isGreaterThanOrEqualTo(com.asmolabs.vectispire.core.access.AuthServiceDeadline.value());
        org.assertj.core.api.Assertions.assertThat(java.time.Duration.ofNanos(done - wrongPassword))
                .isGreaterThanOrEqualTo(com.asmolabs.vectispire.core.access.AuthServiceDeadline.value());

        // The next code, since enrolment used the current one and a code opens once.
        mvc.perform(signIn(username, PASSWORD, Totp.generateCode(secret, clock.instant().plusSeconds(30))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").isString())
                .andExpect(jsonPath("$.mfa_required").value(false));
    }

    @Test
    @DisplayName("an account with no second factor is refused past the budget, with or without a code")
    void noSecondFactorNoWayPast() throws Exception {
        String username = "plain-" + System.nanoTime();
        tokenFor(username, Role.USER, false);
        spendTheBudget(users.findByUsername(username).orElseThrow().getId());

        mvc.perform(signIn(username, PASSWORD, "123456"))
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.code").value("account-throttled"));
    }

    private String enrolSecondFactor(String token) throws Exception {
        String setup = mvc.perform(authenticated(post("/api/v1/auth/mfa/setup"), token))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        String secret = com.jayway.jsonpath.JsonPath.read(setup, "$.secret");
        mvc.perform(authenticated(post("/api/v1/auth/mfa/enable"), token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"password\":\"" + PASSWORD + "\",\"secret\":\"" + secret + "\",\"code\":\""
                                + Totp.generateCode(secret, clock.instant()) + "\"}"))
                .andExpect(status().isOk());
        return secret;
    }

    private void spendTheBudget(long accountId) {
        for (int failure = 0; failure < LoginThrottle.MAX_ATTEMPTS_PER_ACCOUNT; failure++) {
            LoginAttemptEntity row = new LoginAttemptEntity();
            row.setCounterKey(LoginThrottle.accountKey(accountId));
            row.setOccurredAt(clock.instant().minusSeconds(5));
            attempts.save(row);
        }
    }

    /** From an address the account has never signed in from. */
    private MockHttpServletRequestBuilder signIn(String username, String password, String code) {
        return post("/api/v1/auth/login")
                .with(request -> {
                    request.setRemoteAddr("203.0.113.80");
                    return request;
                })
                .contentType(MediaType.APPLICATION_JSON)
                .content(write(new com.asmolabs.vectispire.core.access.web.AuthController.LoginRequest(username, password, code)));
    }
}
