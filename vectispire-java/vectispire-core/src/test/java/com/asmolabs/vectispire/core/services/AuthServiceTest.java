package com.asmolabs.zanshin.core.services;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.asmolabs.zanshin.common.domain.audit.AuditOperation;
import com.asmolabs.zanshin.common.domain.auth.LoginThrottle;
import com.asmolabs.zanshin.common.domain.auth.Sessions;
import com.asmolabs.zanshin.common.domain.crypto.PasswordHasher;
import com.asmolabs.zanshin.core.persistence.LoginAttemptEntity;
import com.asmolabs.zanshin.core.persistence.SessionEntity;
import com.asmolabs.zanshin.core.persistence.UserEntity;
import com.asmolabs.zanshin.core.repositories.LoginAttempts;
import com.asmolabs.zanshin.core.repositories.UserSessions;
import com.asmolabs.zanshin.core.repositories.Users;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("logging in, and being refused")
class AuthServiceTest {

    private static final Instant NOW = Instant.parse("2026-08-18T10:00:00Z");
    private static final String PASSWORD = "correct horse battery staple";

    private Users users;
    private UserSessions sessions;
    private LoginAttempts attempts;
    private AuthService service;

    private final List<LoginAttemptEntity> recorded = new ArrayList<>();

    @BeforeEach
    void wire() {
        users = mock(Users.class);
        sessions = mock(UserSessions.class);
        attempts = mock(LoginAttempts.class);
        service = new AuthService(users, sessions, attempts, Sessions.Policy.DEFAULT, Clock.fixed(NOW, ZoneOffset.UTC));

        recorded.clear();
        when(attempts.findByCounterKeyAndOccurredAtAfter(anyString(), any())).thenReturn(List.of());
        when(attempts.save(any())).thenAnswer(call -> {
            recorded.add(call.getArgument(0));
            return call.getArgument(0);
        });
        when(sessions.save(any())).thenAnswer(call -> call.getArgument(0));
        when(users.findByUsername("alice")).thenReturn(Optional.of(user("alice", true)));
    }

    @Test
    void opensASessionOnTheRightPassword() {
        AuthService.LoginResult result = service.login(request("alice", PASSWORD));

        assertThat(result.outcome()).isInstanceOfSatisfying(AuthService.Outcome.Success.class, success -> {
            assertThat(success.issued().token()).isNotBlank();
            // The clear token is handed out; the row keeps its hash and nothing else.
            assertThat(success.issued().session().getTokenHash())
                    .isEqualTo(Sessions.hashOf(success.issued().token()))
                    .isNotEqualTo(success.issued().token());
            assertThat(success.issued().session().getExpiresAt())
                    .isEqualTo(NOW.plus(Sessions.Policy.DEFAULT.absoluteLifetime()));
        });
        assertThat(result.audit().operation()).isEqualTo(AuditOperation.LOGIN_SUCCESS);
        // A success clears both counters: five mistypes then the right password is not an attack.
        verify(attempts).deleteByCounterKey(LoginThrottle.userKey("alice"));
        verify(attempts).deleteByCounterKey(LoginThrottle.clientKey("browser-1"));
    }

    @Test
    @DisplayName("a wrong password, an unknown account and a disabled one are one outcome")
    void allThreeFailuresLookAlike() {
        when(users.findByUsername("bob")).thenReturn(Optional.of(user("bob", false)));

        assertThat(service.login(request("alice", "wrong")).outcome()).isInstanceOf(AuthService.Outcome.Invalid.class);
        assertThat(service.login(request("nobody", PASSWORD)).outcome()).isInstanceOf(AuthService.Outcome.Invalid.class);
        assertThat(service.login(request("bob", PASSWORD)).outcome()).isInstanceOf(AuthService.Outcome.Invalid.class);
    }

    @Test
    @DisplayName("a failure counts against the user and against the client")
    void bothCountersAdvance() {
        service.login(request("alice", "wrong"));

        assertThat(recorded).extracting(LoginAttemptEntity::getCounterKey)
                .containsExactlyInAnyOrder(LoginThrottle.userKey("alice"), LoginThrottle.clientKey("browser-1"));
    }

    @Test
    @DisplayName("a throttled attempt costs no password verification at all")
    void theThrottleComesFirst() {
        when(attempts.findByCounterKeyAndOccurredAtAfter(eqUserKey(), any()))
                .thenReturn(fiveRecentAttempts());

        AuthService.LoginResult result = service.login(request("alice", PASSWORD));

        assertThat(result.outcome()).isInstanceOf(AuthService.Outcome.Blocked.class);
        assertThat(result.audit().operation()).isEqualTo(AuditOperation.LOGIN_BLOCKED);
        // The account is never even loaded: otherwise each refused attempt would burn more CPU
        // than it saves, and the throttle would become the denial-of-service lever.
        verify(users, never()).findByUsername(anyString());
    }

    @Test
    @DisplayName("an idle session is deleted, not merely refused")
    void anExpiredSessionIsRemoved() {
        SessionEntity session = new SessionEntity();
        session.setTokenHash(Sessions.hashOf("t"));
        session.setCreatedAt(NOW.minus(Sessions.Policy.DEFAULT.absoluteLifetime()).minusSeconds(1));
        session.setLastSeenAt(NOW);
        // Stubbed on the hash, which is what the lookup asks for: a stub on the clear token
        // would answer nothing and the test would pass for the wrong reason.
        when(sessions.findById(Sessions.hashOf("t"))).thenReturn(Optional.of(session));

        assertThat(service.resolve("Bearer t")).isEmpty();
        verify(sessions).deleteById(Sessions.hashOf("t"));
    }

    @Test
    void refreshesTheActivityOfALiveSession() {
        SessionEntity session = new SessionEntity();
        session.setTokenHash(Sessions.hashOf("t"));
        session.setCreatedAt(NOW.minusSeconds(60));
        session.setLastSeenAt(NOW.minusSeconds(60));
        when(sessions.findById(Sessions.hashOf("t"))).thenReturn(Optional.of(session));

        assertThat(service.resolve("Bearer t")).get().returns(NOW, SessionEntity::getLastSeenAt);
    }

    @Test
    void ignoresAMissingOrMalformedHeader() {
        assertThat(service.resolve(null)).isEmpty();
        assertThat(service.resolve("Basic dXNlcjpwYXNz")).isEmpty();
    }

    private static String eqUserKey() {
        return org.mockito.ArgumentMatchers.eq(LoginThrottle.userKey("alice"));
    }

    private static List<LoginAttemptEntity> fiveRecentAttempts() {
        List<LoginAttemptEntity> failures = new ArrayList<>();
        for (int i = 0; i < LoginThrottle.MAX_ATTEMPTS_PER_USER; i++) {
            LoginAttemptEntity attempt = new LoginAttemptEntity();
            attempt.setOccurredAt(NOW.minusSeconds(10));
            failures.add(attempt);
        }
        return failures;
    }

    private static AuthService.LoginRequest request(String username, String password) {
        return new AuthService.LoginRequest(username, password, "browser-1", "curl/8", "10.0.0.1");
    }

    private static UserEntity user(String username, boolean active) {
        UserEntity user = new UserEntity();
        user.setId(1L);
        user.setUsername(username);
        user.setPassword(PasswordHasher.hash(PASSWORD));
        user.setIsActive(active);
        return user;
    }
}
