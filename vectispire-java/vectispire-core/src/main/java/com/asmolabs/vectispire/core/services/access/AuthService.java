package com.asmolabs.vectispire.core.services.access;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.auth.LoginThrottle;
import com.asmolabs.vectispire.common.domain.auth.Sessions;
import com.asmolabs.vectispire.common.domain.crypto.PasswordHasher;
import com.asmolabs.vectispire.common.domain.siem.SecurityEventType;
import com.asmolabs.vectispire.core.services.audit.AuditLogService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

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
     * @param ipAddress the client's address as {@code TrustedProxies} resolves it, and the key of
     *     the second counter. It used to be a {@code client_id} the browser chose, on the grounds
     *     that an office behind one NAT would otherwise share a lock — but a key the caller
     *     chooses is a counter the caller resets: a fresh id on every attempt, and the client
     *     ceiling never fired. Twenty failures a quarter of an hour from one egress is the cost
     *     accepted for a ceiling that exists.
     */
    public record LoginRequest(String username, String password, String userAgent, String ipAddress) {}

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

        /** The password was right and the account owes a code. No session exists yet. */
        record SecondFactorRequired(UserEntity user) implements Outcome {}

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
        // Looked up before the throttle, which costs a query and no hashing. The account is
        // what the counter protects, and the username the caller typed is not the account: the
        // lookup follows the database's collation, which on MySQL ignores case and accents, so
        // "Alice", "alice" and "Àlice" were three counters opening one account — five tries each.
        Optional<UserEntity> user = users.findByUsername(request.username());
        String userKey = user.map(found -> LoginThrottle.accountKey(found.getId()))
                .orElseGet(() -> LoginThrottle.userKey(request.username()));
        String clientKey = LoginThrottle.clientKey(String.valueOf(request.ipAddress()));

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
                                    request.username())
                            // The ceiling, and not "password sign-in is off", which shares the
                            // operation: only the writer can tell the two apart.
                            .signalling(SecurityEventType.SIGN_IN_THROTTLED));
        }

        // **One key derivation whatever the name, so the answer's timing says nothing.** The hash
        // used to be verified only when an account was found, on the grounds that a derivation for
        // every unknown name was a denial-of-service lever: an unknown name answered in
        // microseconds, a known one after Argon2 — an account-existence oracle the uniform 401
        // message was built to prevent. The lever argument did not hold: the throttle above has
        // already admitted this attempt, and a known name buys the same derivation at the same
        // rate. A deactivated account is verified against the same stand-in, for the same reason.
        Optional<UserEntity> active = user.filter(UserEntity::getIsActive);
        boolean matches = PasswordHasher.verify(
                request.password(), active.map(UserEntity::getPassword).orElseGet(AuthService::standInHash));
        boolean authenticated = active.isPresent() && matches;

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
        rehashIfStale(found, request.password());
        if (found.getMfaEnabled()) {
            // **No session yet.** One was opened here for every account and discarded by the
            // caller when a code was owed: a row per password exchange that nobody could present,
            // living its full lifetime in the sessions table. The session is opened when the code
            // is verified, and not before.
            return new LoginResult(
                    new Outcome.SecondFactorRequired(found),
                    AuditLogService.Record.of(
                            AuditOperation.LOGIN_SUCCESS, found.getUsername(),
                            "Password accepted, second factor required", found.getUsername()));
        }
        IssuedSession session = openSession(found, request, now);
        return new LoginResult(
                new Outcome.Success(session, found),
                AuditLogService.Record.of(
                        AuditOperation.LOGIN_SUCCESS, found.getUsername(), "Login succeeded", found.getUsername()));
    }

    /**
     * The account a session belongs to, if it may still act.
     *
     * <p>Asked by the bearer filter after {@link #resolve}: a session outlives nothing about its
     * account, so a deactivated account's session is refused — and closed — here rather than
     * honoured until it expires. Behind a service because a filter in {@code api} does not reach
     * repositories, any more than a controller does.
     */
    @Transactional(readOnly = true)
    public Optional<UserEntity> activeUserOf(SessionEntity session) {
        return users.findById(session.getUserId()).filter(UserEntity::getIsActive);
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

        // Throttled: see `Sessions.shouldRecordActivity`. Writing here on every request turned any
        // page making several calls into a fight between its own requests over one row.
        if (!Sessions.shouldRecordActivity(session.getLastSeenAt(), now, policy)) {
            return Optional.of(session);
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
        return openSession(user, new LoginRequest(user.getUsername(), null, userAgent, ipAddress), clock.instant());
    }

    @Transactional
    public IssuedSession openFederatedSession(UserEntity user, String userAgent, String ipAddress) {
        return openSession(user, new LoginRequest(user.getUsername(), null, userAgent, ipAddress), clock.instant());
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

    /**
     * How long this account must wait before presenting another second-factor code; zero when
     * it may. Asked before the code is checked, for the reason the password throttle is.
     */
    @Transactional(readOnly = true)
    public Duration secondFactorLockout(Long accountId) {
        Instant now = clock.instant();
        return LoginThrottle.decide(
                        occurrences(LoginThrottle.secondFactorKey(accountId), now.minus(LoginThrottle.WINDOW)),
                        LoginThrottle.MAX_SECOND_FACTOR_FAILURES,
                        now)
                .retryAfter();
    }

    @Transactional
    public void recordSecondFactorFailure(Long accountId) {
        recordFailure(LoginThrottle.secondFactorKey(accountId), clock.instant());
    }

    /** Only a right code clears it — never a right password, which is the whole point. */
    @Transactional
    public void clearSecondFactorFailures(Long accountId) {
        attempts.deleteByCounterKey(LoginThrottle.secondFactorKey(accountId));
    }

    /** A real Argon2 hash of nothing anybody knows, computed once, for the unknown-name path. */
    private static volatile String standIn;

    private static String standInHash() {
        String hash = standIn;
        if (hash == null) {
            hash = PasswordHasher.hash(java.util.UUID.randomUUID().toString());
            standIn = hash;
        }
        return hash;
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

    /**
     * Rewrites a password hash that was made under weaker parameters than today's.
     *
     * <p><b>The PHC format exists to make this possible, and nothing was doing it.</b>
     * {@code PasswordHasher} stores {@code m=…,t=…,p=…} alongside every hash so that an old one
     * still verifies under its own cost, and its javadoc promised the hash "can be rewritten on
     * the next successful login". {@code needsRehash} was written, tested, and called from no
     * production code at all — so raising Argon2id's cost would have left every existing account
     * at the old parameters for ever, which is the whole thing the format was chosen to avoid.
     *
     * <p>Here and not at verification time: this runs only after the password was accepted, so a
     * wrong guess never causes a write, and the plaintext is in hand exactly once.
     *
     * <p>A failure to save is swallowed on purpose. The sign-in succeeded and the stored hash is
     * still valid under its own parameters; refusing the session over a housekeeping write would
     * turn a cost upgrade into an outage.
     */
    private void rehashIfStale(UserEntity user, String password) {
        if (!PasswordHasher.needsRehash(user.getPassword())) {
            return;
        }
        try {
            user.setPassword(PasswordHasher.hash(password));
            users.save(user);
        } catch (RuntimeException couldNotSave) {
            log.warn("Could not rewrite the password hash for \"{}\" under current parameters.",
                    user.getUsername(), couldNotSave);
        }
    }

}
