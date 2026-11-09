package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.crypto.PasswordHasher;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.access.AuthService;
import com.asmolabs.vectispire.core.access.UserView;
import com.asmolabs.vectispire.core.access.persistence.UserEntity;
import com.asmolabs.vectispire.core.access.persistence.SessionEntity;
import com.asmolabs.vectispire.core.access.persistence.SessionRepository;
import com.asmolabs.vectispire.core.access.persistence.UserRepository;
import com.asmolabs.vectispire.common.domain.auth.Sessions;
import com.asmolabs.vectispire.core.access.web.security.chain.OidcConfiguration;
import jakarta.servlet.http.Cookie;
import java.time.Instant;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * The single sign-on hand-off, traded for a session once.
 *
 * <p>The cookie the provider's redirect leaves carries the session the sign-on minted, and the
 * exchange handed that same token back for as long as the cookie lived, to whoever presented it.
 */
@DisplayName("the single sign-on hand-off")
class SessionExchangeRoutesTest extends ApiTestBase {

    @Autowired
    private AuthService auth;

    @Autowired
    private UserRepository users;

    @Test
    @DisplayName("is exchanged once, for a session of its own; a second presentation finds nothing")
    void isExchangedOnce() throws Exception {
        UserEntity user = new UserEntity();
        user.setUsername("federated-" + System.nanoTime());
        user.setPassword(PasswordHasher.hash("unused by a federated sign-in"));
        user.setRole(Role.USER.name());
        user.setIsActive(true);
        user.setMustChangePassword(false);
        user.setCreatedAt(Instant.now());
        user.setUpdatedAt(Instant.now());
        UserView account = UserView.of(users.save(user));
        String handoff = auth.openHandoff(account, "browser", "198.51.100.7").token();
        Cookie cookie = new Cookie(OidcConfiguration.HANDOFF_COOKIE, handoff);

        String body = mvc.perform(post("/api/v1/auth/session/exchange").cookie(cookie))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        String session = json.readTree(body).get("token").asText();

        assertThat(session).isNotEqualTo(handoff);
        mvc.perform(authenticated(get("/api/v1/auth/me"), session)).andExpect(status().isOk());
        // The hand-off is spent: neither as a cookie nor as a bearer does it open anything now.
        mvc.perform(post("/api/v1/auth/session/exchange").cookie(cookie)).andExpect(status().isUnauthorized());
        mvc.perform(authenticated(get("/api/v1/auth/me"), handoff)).andExpect(status().isUnauthorized());
    }

    /**
     * The audit of 10 October 2026: the hand-off was a session like any other, so its cookie's
     * value, presented as a bearer, opened the API for the session's hour without being exchanged.
     */
    @Test
    @DisplayName("is not a bearer token, even before it is exchanged")
    void isNotABearerBeforeTheExchange() throws Exception {
        String handoff = auth.openHandoff(account(), "browser", "198.51.100.7").token();

        mvc.perform(authenticated(get("/api/v1/auth/me"), handoff)).andExpect(status().isUnauthorized());
        // And the refusal spent nothing: the browser's exchange still succeeds.
        mvc.perform(post("/api/v1/auth/session/exchange").cookie(new Cookie(OidcConfiguration.HANDOFF_COOKIE, handoff)))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("expires with its cookie, sixty seconds after the sign-on")
    void expiresWithItsCookie() throws Exception {
        String handoff = "handoff-kept-past-its-minute";
        SessionEntity row = new SessionEntity();
        row.setTokenHash(Sessions.handoffHashOf(handoff));
        row.setUserId(account().id());
        row.setCreatedAt(Instant.now().minus(Sessions.HANDOFF_LIFETIME).minusSeconds(5));
        row.setLastSeenAt(row.getCreatedAt());
        row.setExpiresAt(row.getCreatedAt().plus(Sessions.HANDOFF_LIFETIME));
        sessions.save(row);

        mvc.perform(post("/api/v1/auth/session/exchange").cookie(new Cookie(OidcConfiguration.HANDOFF_COOKIE, handoff)))
                .andExpect(status().isUnauthorized());
        assertThat(sessions.findById(Sessions.handoffHashOf(handoff))).isEmpty();
    }

    @Autowired
    private SessionRepository sessions;

    private UserView account() {
        UserEntity user = new UserEntity();
        user.setUsername("federated-" + System.nanoTime());
        user.setPassword(PasswordHasher.hash("unused by a federated sign-in"));
        user.setRole(Role.USER.name());
        user.setIsActive(true);
        user.setMustChangePassword(false);
        user.setCreatedAt(Instant.now());
        user.setUpdatedAt(Instant.now());
        return UserView.of(users.save(user));
    }
}
