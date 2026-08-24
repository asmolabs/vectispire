package com.asmolabs.vectispire.core.services;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.auth.LoginThrottle;
import com.asmolabs.vectispire.common.domain.auth.Sessions;
import com.asmolabs.vectispire.common.domain.crypto.PasswordHasher;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.persistence.UserEntity;
import com.asmolabs.vectispire.core.repositories.LoginAttempts;
import com.asmolabs.vectispire.core.repositories.UserSessions;
import com.asmolabs.vectispire.core.repositories.Users;
import java.time.Instant;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * Authentication against a database.
 *
 * <p>The unit suite proves the ordering with fakes. What only a database shows is that the
 * throttle's counters are really written and really counted — the query is a window on a
 * timestamp column, and a throttle that counts nothing is a throttle that is not there.
 */
@DisplayName("logging in, against a database")
class AuthDatabaseTest extends VectispireContextTest {

    private static final String PASSWORD = "correct horse battery staple";

    @Autowired
    private AuthService auth;

    @Autowired
    private Users users;

    @Autowired
    private UserSessions sessions;

    @Autowired
    private LoginAttempts attempts;

    @BeforeEach
    void seedAccount() {
        UserEntity user = new UserEntity();
        user.setUsername("alice");
        user.setPassword(PasswordHasher.hash(PASSWORD));
        user.setRole(Role.ADMIN.name());
        user.setIsActive(true);
        user.setCreatedAt(Instant.now());
        user.setUpdatedAt(Instant.now());
        users.save(user);
    }

    @Test
    @DisplayName("a session is written, and resolves back")
    void aSessionSurvivesTheRoundTrip() {
        AuthService.LoginResult result = auth.login(request("alice", PASSWORD));

        assertThat(result.outcome()).isInstanceOf(AuthService.Outcome.Success.class);
        String token = ((AuthService.Outcome.Success) result.outcome()).issued().token();
        assertThat(auth.resolve("Bearer " + token)).isPresent();
    }

    @Test
    @DisplayName("what the store holds is a verifier, not the token")
    void theStoredValueDoesNotAuthenticate() {
        String token = ((AuthService.Outcome.Success) auth.login(request("alice", PASSWORD)).outcome())
                .issued()
                .token();

        // The property, checked against a real row rather than against the mapping: nothing in
        // the table equals the token, and the value that is there is its hash. A dump of
        // `t_session` therefore hands over no session — which is the entire point.
        assertThat(sessions.findAll()).singleElement().satisfies(row -> {
            assertThat(row.getTokenHash()).isNotEqualTo(token).isEqualTo(Sessions.hashOf(token));
            // And presenting the stored value does not get in. Reading the table is not enough;
            // one would have to invert SHA-256.
            assertThat(auth.resolve("Bearer " + row.getTokenHash())).isEmpty();
        });
        assertThat(sessions.findById(token)).isEmpty();
    }

    @Test
    @DisplayName("the throttle counts real rows, and locks after five")
    void theThrottleActuallyCounts() {
        for (int attempt = 0; attempt < LoginThrottle.MAX_ATTEMPTS_PER_USER; attempt++) {
            assertThat(auth.login(request("alice", "wrong")).outcome())
                    .isInstanceOf(AuthService.Outcome.Invalid.class);
        }

        // Each failure writes two rows — one per counter — and the sixth attempt is refused
        // before the password is judged at all.
        assertThat(attempts.findAll()).hasSize(2 * LoginThrottle.MAX_ATTEMPTS_PER_USER);
        assertThat(auth.login(request("alice", PASSWORD)).outcome())
                .isInstanceOf(AuthService.Outcome.Blocked.class);
    }

    @Test
    @DisplayName("a success clears the counters, so five mistypes then the right password is not an attack")
    void successClearsWhatCameBefore() {
        auth.login(request("alice", "wrong"));
        auth.login(request("alice", "wrong"));

        assertThat(auth.login(request("alice", PASSWORD)).outcome())
                .isInstanceOf(AuthService.Outcome.Success.class);
        assertThat(attempts.findAll()).isEmpty();
    }

    @Test
    @DisplayName("signing out really removes the row")
    void revokingDeletes() {
        AuthService.IssuedSession issued =
                ((AuthService.Outcome.Success) auth.login(request("alice", PASSWORD)).outcome()).issued();

        auth.revoke(issued.session());

        assertThat(sessions.findById(issued.session().getTokenHash())).isEmpty();
        assertThat(auth.resolve("Bearer " + issued.token())).isEmpty();
    }

    @Test
    @DisplayName("a deactivated account cannot sign in, and its message is the ordinary refusal")
    void aDeactivatedAccountIsRefusedLikeAnyOther() {
        UserEntity user = users.findByUsername("alice").orElseThrow();
        user.setIsActive(false);
        users.save(user);

        assertThat(auth.login(request("alice", PASSWORD)).outcome())
                .isInstanceOf(AuthService.Outcome.Invalid.class);
    }

    private static AuthService.LoginRequest request(String username, String password) {
        return new AuthService.LoginRequest(username, password, "browser-1", "curl/8", "10.0.0.1");
    }
}
