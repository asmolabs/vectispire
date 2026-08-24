package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.auth.LoginThrottle;
import com.asmolabs.vectispire.common.domain.auth.Sessions;
import com.asmolabs.vectispire.common.domain.crypto.PasswordHasher;
import com.asmolabs.vectispire.core.persistence.LoginAttemptEntity;
import com.asmolabs.vectispire.core.persistence.SessionEntity;
import com.asmolabs.vectispire.core.persistence.UserEntity;
import com.asmolabs.vectispire.core.repositories.LoginAttempts;
import com.asmolabs.vectispire.core.repositories.UserSessions;
import com.asmolabs.vectispire.core.repositories.Users;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Authentication assembled: throttle, verification, session.
 *
 * <p>The order of the three is not incidental. <b>The throttle comes before any password
 * comparison</b>: a locked account must cost no key-derivation work, or the throttle becomes
 * the denial-of-service lever itself — each refused attempt burning more CPU than it saves.
 *
 * <p>All three outcomes are audited — success, failure, block — because a log that records
 * only failures cannot tell "somebody mistyped twice" from "somebody is walking the account
 * list from one host".
 */
@Service
public class AuthService {

    private final Users users;
    private final UserSessions sessions;
    private final LoginAttempts attempts;
    private final Sessions.Policy policy;
    private final Clock clock;

    public AuthService(
            Users users,
            UserSessions sessions,
            LoginAttempts attempts,
            Sessions.Policy policy,
            Clock clock) {
        this.users = users;
        this.sessions = sessions;
        this.attempts = attempts;
        this.policy = policy;
        this.clock = clock;
    }

    /**
     * @param clientId identifies the client, for the second counter. Never an IP address alone:
     *     behind a corporate NAT everybody would share one lock
     */
    public record LoginRequest(String username, String password, String clientId, String userAgent, String ipAddress) {}

    /** A login's outcome, and what the caller must write to the audit log. */
    public sealed interface Outcome {

        /**
         * @param issued the row, plus the clear token — which exists nowhere else. The store
         *     holds its hash, so this record is the only chance the caller has to send it; there
         *     is no reading it back afterwards.
         */
        record Success(IssuedSession issued, UserEntity user) implements Outcome {}

        /**
         * Wrong password, unknown account, or a deactivated one.
         *
         * <p>The three are one case on purpose: telling them apart from the outside turns the
         * login form into an account-existence oracle.
         */
        record Invalid() implements Outcome {}

        record Blocked(Duration retryAfter) implements Outcome {}
    }

    /**
     * A session that has just been opened: the row, and the token the client must be given.
     *
     * <p>The two travel together for the length of one request and then part: the token goes out
     * over HTTPS and is forgotten, the row stays with only its hash. Any caller that needs to
     * *identify* the session later — to revoke it, or to spare it — uses
     * {@link SessionEntity#getTokenHash()}; only a caller handing the session to its owner uses
     * {@link #token()}.
     */
    public record IssuedSession(SessionEntity session, String token) {}

    /**
     * @param audit returned rather than written here, so this service does not depend on the
     *     audit log and stays testable alone
     */
    public record LoginResult(Outcome outcome, AuditLogService.Record audit) {}

    @Transactional
    public LoginResult login(LoginRequest request) {
        Instant now = clock.instant();
        Instant since = now.minus(LoginThrottle.WINDOW);
        String userKey = LoginThrottle.userKey(request.username());
        String clientKey = LoginThrottle.clientKey(request.clientId());

        LoginThrottle.Decision throttle = LoginThrottle.decide(
                new LoginThrottle.Attempts(occurrences(userKey, since), occurrences(clientKey, since)), now);

        if (!throttle.allowed()) {
            // Refused before any hashing: that is the point of checking first.
            return new LoginResult(
                    new Outcome.Blocked(throttle.retryAfter()),
                    AuditLogService.Record.of(
                            AuditOperation.LOGIN_BLOCKED,
                            request.username(),
                            "Attempt refused by the throttle (" + throttle.retryAfter().toSeconds() + "s to wait)",
                            request.username()));
        }

        Optional<UserEntity> user = users.findByUsername(request.username()).filter(UserEntity::getIsActive);
        // The hash is verified only when an account was found. Verifying it anyway to equalize
        // timings would mean a free key derivation for every unknown username, which is a
        // denial-of-service lever; the timing difference is real, and the throttle above is what
        // makes it unexploitable.
        boolean authenticated =
                user.filter(found -> PasswordHasher.verify(request.password(), found.getPassword())).isPresent();

        if (!authenticated) {
            recordFailure(userKey, now);
            recordFailure(clientKey, now);
            return new LoginResult(
                    new Outcome.Invalid(),
                    AuditLogService.Record.of(
                            AuditOperation.LOGIN_FAILURE,
                            request.username(),
                            // Deliberately silent on whether the account exists: the log is read
                            // by humans, but an over-precise answer ends up leaking into an error
                            // message.
                            "Login failed",
                            request.username()));
        }

        attempts.deleteByCounterKey(userKey);
        attempts.deleteByCounterKey(clientKey);

        UserEntity found = user.orElseThrow();
        IssuedSession session = openSession(found, request, now);
        return new LoginResult(
                new Outcome.Success(session, found),
                AuditLogService.Record.of(
                        AuditOperation.LOGIN_SUCCESS, found.getUsername(), "Login succeeded", found.getUsername()));
    }

    /**
     * Resolves a token into an active session, refreshing its activity timestamp.
     *
     * <p>An expired session is <b>deleted</b> rather than merely refused: leaving it would grow
     * the table with rows that will never serve again, and the scheduler's purge would be left
     * collecting what nobody touched.
     */
    @Transactional
    public Optional<SessionEntity> resolve(String authorizationHeader) {
        Optional<String> token = Sessions.bearerToken(authorizationHeader);
        if (token.isEmpty()) {
            return Optional.empty();
        }

        // The presented token is hashed before it touches the store: what is indexed is the
        // hash, and a caller who somehow read the table would hold hashes of tokens rather than
        // tokens. This is the line that makes that true — a `findById(token)` here would still
        // work for every legitimate caller, and would quietly restore the old property.
        Optional<SessionEntity> found = sessions.findById(Sessions.hashOf(token.get()));
        if (found.isEmpty()) {
            return Optional.empty();
        }

        SessionEntity session = found.get();
        Instant now = clock.instant();
        if (!Sessions.isActive(session.getCreatedAt(), session.getLastSeenAt(), now, policy)) {
            sessions.deleteById(session.getTokenHash());
            return Optional.empty();
        }

        session.setLastSeenAt(now);
        return Optional.of(sessions.save(session));
    }

    /**
     * A real logout: the row disappears and the token is worth nothing.
     *
     * <p>Takes the row rather than the token because the row is what every caller has — the
     * bearer filter and the logout route both hold a resolved session — and because a
     * {@code revoke(String)} would accept either the token or its hash, one of which silently
     * revokes nothing.
     */
    @Transactional
    public void revoke(SessionEntity session) {
        sessions.deleteById(session.getTokenHash());
    }

    /**
     * Closes every session of an account.
     *
     * <p>Called after a password change: leaving open the sessions of a password that has just
     * been replaced would empty the gesture of its meaning.
     */
    @Transactional
    public void revokeAllForUser(long userId) {
        sessions.deleteByUserId(userId);
    }

    /**
     * A session for somebody an identity provider vouched for.
     *
     * <p><b>The same session a password produces, deliberately.</b> Everything downstream — the
     * bearer filter, the principal, the visibility restriction, the audit trail, the absolute and
     * idle lifetimes, the rule that a role change closes the sessions — reads a row of
     * {@code t_session} and nothing else. A second kind of session for federated users would
     * mean re-deciding all of that a second time, and the two answers would drift.
     *
     * <p>No throttle here: the counter protects a password, and there is no password to guess.
     * The provider owns that side, and a failed sign-on never reaches this method.
     */
    @Transactional
    public IssuedSession openSessionForUser(UserEntity user, String userAgent, String ipAddress) {
        return openSession(user, new LoginRequest(user.getUsername(), null, null, userAgent, ipAddress), clock.instant());
    }

    @Transactional
    public IssuedSession openFederatedSession(UserEntity user, String userAgent, String ipAddress) {
        return openSession(user, new LoginRequest(user.getUsername(), null, null, userAgent, ipAddress), clock.instant());
    }

    private IssuedSession openSession(UserEntity user, LoginRequest request, Instant now) {
        Sessions.IssuedToken minted = Sessions.issue();
        SessionEntity session = new SessionEntity();
        session.setTokenHash(minted.hash());
        session.setUserId(user.getId());
        session.setCreatedAt(now);
        session.setLastSeenAt(now);
        session.setExpiresAt(now.plus(policy.absoluteLifetime()));
        session.setUserAgent(clip(request.userAgent()));
        session.setIpAddress(request.ipAddress());
        return new IssuedSession(sessions.save(session), minted.token());
    }

    private List<Instant> occurrences(String counterKey, Instant since) {
        return attempts.findByCounterKeyAndOccurredAtAfter(counterKey, since).stream()
                .map(LoginAttemptEntity::getOccurredAt)
                .toList();
    }

    private void recordFailure(String counterKey, Instant now) {
        LoginAttemptEntity attempt = new LoginAttemptEntity();
        attempt.setCounterKey(counterKey);
        attempt.setOccurredAt(now);
        attempts.save(attempt);
    }

    private static String clip(String value) {
        if (value == null) {
            return null;
        }
        return value.length() <= 255 ? value : value.substring(0, 255);
    }
}
