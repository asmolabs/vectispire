package com.asmolabs.vectispire.core.api;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.users.Role;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;

@DisplayName("the authentication routes")
class AuthRoutesTest extends ApiTestBase {

    @Test
    @DisplayName("an unauthenticated call to a protected route is 401, not 403")
    void anonymousIsUnauthorized() throws Exception {
        // The distinction matters to the client: 401 sends it to the login screen, 403 tells it
        // to show "you do not have the rights" to somebody who is not signed in at all.
        mvc.perform(get("/api/v1/issues")).andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("the sign-in methods say a password is accepted here")
    void methodsReportsTheOpenDoors() throws Exception {
        // Read before anybody is authenticated, because the screen has to know which inputs to
        // draw. The test build configures no issuer, so this is the ordinary deployment: a
        // password works, single sign-on is absent rather than present and refusing.
        mvc.perform(get("/api/v1/auth/methods"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.password").value(true))
                .andExpect(jsonPath("$.configured").value(false));
    }

    @Test
    @DisplayName("the account throttle says how long to wait in a header, not only in a sentence")
    void theThrottleAnswersWithRetryAfter() throws Exception {
        // **Two limiters guard this endpoint, and they disagreed about the contract.**
        // `LoginRateLimitFilter` keys on the caller's address and has always returned
        // `Retry-After`; this one keys on the account and returned a bare 429 whose wait was
        // legible only inside an English sentence. Which of the two fires first depends on
        // whether the attempts share an address or a username — so a client honouring the header
        // got an answer or got nothing depending on how it was being attacked.
        //
        // Six wrong passwords for one account: the per-user ceiling is five, and six stays well
        // under the address limiter's ten, so this exercises the account path and not the filter.
        tokenFor("throttled-account", Role.USER, false);

        for (int attempt = 0; attempt < 6; attempt++) {
            mvc.perform(post("/api/v1/auth/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(write(Map.of("username", "throttled-account", "password", "wrong-on-purpose", "client_id", "t"))));
        }

        mvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("username", "throttled-account", "password", "wrong-on-purpose", "client_id", "t"))))
                .andExpect(status().isTooManyRequests())
                // The value, not merely the presence: a header carrying a word instead of a
                // number is a header every client will ignore, and `exists` would call it a pass.
                .andExpect(header().string("Retry-After", org.hamcrest.Matchers.matchesPattern("[1-9]\\d*")))
                .andExpect(header().string(
                        "X-Rate-Limit-Retry-After-Seconds", org.hamcrest.Matchers.matchesPattern("[1-9]\\d*")));
    }

    @Test
    @DisplayName("login refuses a wrong password without saying whether the account exists")
    void wrongCredentialsAreOneAnswer() throws Exception {
        tokenFor("someone", Role.USER, false);

        mvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("username", "someone", "password", "wrong", "client_id", "t"))))
                .andExpect(status().isUnauthorized());

        mvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("username", "nobody-at-all", "password", "wrong", "client_id", "t"))))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("login answers a token and the fields the client reads")
    void loginReturnsTheContract() throws Exception {
        tokenFor("alice", Role.ADMIN, false);

        mvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of(
                                "username", "alice",
                                "password", "correct horse battery staple",
                                "client_id", "browser-1"))))
                .andExpect(status().isOk())
                // These four names are the contract the unchanged Angular client reads. A port
                // that renamed one of them would compile, pass every unit test, and blank the
                // login screen.
                .andExpect(jsonPath("$.token").isNotEmpty())
                .andExpect(jsonPath("$.expiresAt").isNotEmpty())
                .andExpect(jsonPath("$.user.username").value("alice"))
                .andExpect(jsonPath("$.user.role").value("ADMIN"))
                .andExpect(jsonPath("$.user.mustChangePassword").value(false));
    }

    @Test
    @DisplayName("\"who am I\" answers the signed-in account")
    void meReturnsTheAccount() throws Exception {
        mvc.perform(authenticated(get("/api/v1/auth/me"), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.role").value("ADMIN"));
    }

    @Test
    @DisplayName("signing out is 204 and the token stops working")
    void logoutRevokesTheToken() throws Exception {
        String token = asAdmin();

        mvc.perform(authenticated(delete("/api/v1/auth/session"), token)).andExpect(status().isNoContent());
        mvc.perform(authenticated(get("/api/v1/auth/me"), token)).andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("a made-up token authenticates nothing")
    void aForgedTokenIsRefused() throws Exception {
        mvc.perform(authenticated(get("/api/v1/auth/me"), "not-a-real-token"))
                .andExpect(status().isUnauthorized());
    }
}
