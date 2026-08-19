package com.asmolabs.zanshin.core.api;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.zanshin.common.domain.users.Role;
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
