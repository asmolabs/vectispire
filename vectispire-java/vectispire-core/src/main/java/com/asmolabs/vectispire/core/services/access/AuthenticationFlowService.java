package com.asmolabs.vectispire.core.services.access;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.auth.Sessions;
import com.asmolabs.vectispire.common.domain.crypto.PasswordHasher;
import com.asmolabs.vectispire.common.domain.siem.SecurityEventType;
import com.asmolabs.vectispire.common.domain.users.AccountRules;
import com.asmolabs.vectispire.core.persistence.MfaChallengeEntity;
import com.asmolabs.vectispire.core.persistence.UserEntity;
import com.asmolabs.vectispire.core.repositories.MfaChallenges;
import com.asmolabs.vectispire.core.repositories.UserSessions;
import com.asmolabs.vectispire.core.repositories.Users;
import com.asmolabs.vectispire.core.services.audit.AuditLogService;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.stereotype.Service;

/**
 * The steps between a person and a session: password, second factor, single sign-on hand-off,
 * and changing one's own password.
 *
 * <p><b>Every outcome is a type, and none of them is an HTTP status.</b> {@code AuthController}
 * decides what each one answers — 401, 403, 429 with {@code Retry-After}, 503 — and this class
 * decides which one happened. The split matters most on the second factor, where the wording of
 * a refusal is itself part of the control: the controller answers the same sentence for a wrong
 * code and for the code that destroyed the challenge, and it can only do that if it is told the
 * difference without being asked to phrase it.
 *
 * <p><b>No transaction spans a flow here, deliberately.</b> Each repository write carries its
 * own, which is how the flows behaved when they lived in the controller, and the attempt counter
 * in particular relies on the database's increment rather than on a surrounding boundary.
 */
@Service
public class AuthenticationFlowService {

    /**
     * **A TOTP code is six digits, so the number of tries is the whole security of the second
     * factor.** Unlimited tries against a five-minute window is a million-code space explored at
     * whatever rate the server sustains, which is not a second factor — it is a delay. Three,
     * then the challenge is destroyed and the password exchange starts again.
     */
    private static final int MAX_MFA_ATTEMPTS = 3;

    /**
     * A bound on how many challenges may be held at once.
     *
     * <p>Each successful password exchange by an MFA-enabled account leaves one entry, and only
     * a success or a later presentation removes it: an abandoned sign-in leaks the entry until
     * something sweeps it. The sweep in {@link #rememberChallenge} clears what has expired, and
     * this cap is what stops the table growing without bound between two sweeps.
     */
    private static final int MAX_MFA_CHALLENGES = 10_000;

    private static final Duration CHALLENGE_LIFETIME = Duration.ofSeconds(300);

    /** Absent when no issuer is configured: single sign-on is optional, and absent when off. */
    private final Optional<ClientRegistrationRepository> providers;

    private final SignInMethodPolicy methods;
    private final AuthService auth;
    private final AuditLogService audit;
    private final TotpService totp;
    private final Users users;
    private final UserSessions sessions;
    private final MfaChallenges mfaChallenges;
    private final Clock clock;

    public AuthenticationFlowService(
            Optional<ClientRegistrationRepository> providers,
            SignInMethodPolicy methods,
            AuthService auth,
            AuditLogService audit,
            TotpService totp,
            Users users,
            UserSessions sessions,
            MfaChallenges mfaChallenges,
            Clock clock) {
        this.providers = providers;
        this.methods = methods;
        this.auth = auth;
        this.audit = audit;
        this.totp = totp;
        this.users = users;
        this.sessions = sessions;
        this.mfaChallenges = mfaChallenges;
        this.clock = clock;
    }

    /**
     * A password presented for exchange.
     *
     * @param ipAddress the client's resolved address, which is also the throttle's second counter
     *     — see {@link AuthService.LoginRequest}
     */
    public record Attempt(String username, String password, String userAgent, String ipAddress) {}

    /** What a password exchange came to. */
    public sealed interface SignIn {
        /** The deployment accepts single sign-on only. Recorded in the audit log before returning. */
        record PasswordDisabled() implements SignIn {}

        record Throttled(Duration retryAfter) implements SignIn {}

        record Refused() implements SignIn {}

        /** The password was right and the account owes a code; the token is the only copy. */
        record ChallengeIssued(String mfaToken) implements SignIn {}

        /**
         * The password was right, but ten thousand live challenges are already waiting. Transient
         * by construction — five minutes clears it — which is why it is not a failure.
         */
        record ChallengesSaturated() implements SignIn {}

        record SignedIn(AuthService.IssuedSession issued, UserView user) implements SignIn {}
    }

    public SignIn signIn(Attempt attempt) {
        if (!methods.passwordAllowed()) {
            audit.record(new AuditLogService.Record(
                    AuditOperation.LOGIN_BLOCKED,
                    attempt.username(),
                    "Password sign-in is disabled on this deployment",
                    attempt.username(),
                    attempt.ipAddress(),
                    attempt.userAgent()));
            return new SignIn.PasswordDisabled();
        }

        AuthService.LoginResult result = auth.login(new AuthService.LoginRequest(
                attempt.username(),
                attempt.password(),
                attempt.userAgent(),
                attempt.ipAddress()));

        audit.record(new AuditLogService.Record(
                result.audit().operation(),
                result.audit().resourceId(),
                result.audit().description(),
                result.audit().userId(),
                attempt.ipAddress(),
                attempt.userAgent(),
                // Carried across: rebuilt without it, the throttle's entry reached the log and the
                // SOC never heard of it.
                result.audit().signal()));

        return switch (result.outcome()) {
            case AuthService.Outcome.Blocked blocked -> new SignIn.Throttled(blocked.retryAfter());
            case AuthService.Outcome.Invalid ignored -> new SignIn.Refused();
            case AuthService.Outcome.SecondFactorRequired owed -> {
                // A locked second factor issues no challenge.
                Duration locked = auth.secondFactorLockout(owed.user().getId());
                if (!locked.isZero()) {
                    yield new SignIn.Throttled(locked);
                }
                String mfaToken = UUID.randomUUID().toString();
                boolean stored = rememberChallenge(
                        mfaToken,
                        owed.user().getId(),
                        clock.instant().plus(CHALLENGE_LIFETIME),
                        attempt.userAgent(),
                        attempt.ipAddress());
                yield stored ? new SignIn.ChallengeIssued(mfaToken) : new SignIn.ChallengesSaturated();
            }
            case AuthService.Outcome.Success success -> new SignIn.SignedIn(success.issued(), UserView.of(success.user()));
        };
    }

    /** What presenting a second-factor code came to. */
    public sealed interface Verification {
        /** Unknown, expired, or destroyed earlier: the caller has to sign in again. */
        record ChallengeInvalid() implements Verification {}

        record AccountMissing() implements Verification {}

        /**
         * A wrong code, whether or not it was the last one allowed. Deliberately one case: which
         * of the two it is would tell an attacker how many tries are left.
         */
        record WrongCode() implements Verification {}

        /** The account has absorbed its wrong codes for this window, whatever challenge carries it. */
        record Throttled(Duration retryAfter) implements Verification {}

        record Verified(AuthService.IssuedSession issued, UserView user) implements Verification {}
    }

    public Verification verify(String mfaToken, String code, String userAgent, String ipAddress) {
        // Hashed before it touches the store, like a session token: what is indexed is not a
        // credential, so a reader of the table holds nothing they can present.
        String challengeKey = Sessions.hashOf(mfaToken);
        MfaChallengeEntity challenge = mfaChallenges.findById(challengeKey).orElse(null);
        if (challenge == null || clock.instant().isAfter(challenge.getExpiresAt())) {
            mfaChallenges.deleteById(challengeKey);
            return new Verification.ChallengeInvalid();
        }

        Optional<UserEntity> account = users.findById(challenge.getUserId());
        if (account.isEmpty()) {
            return new Verification.AccountMissing();
        }
        UserEntity user = account.get();

        Duration locked = auth.secondFactorLockout(user.getId());
        if (!locked.isZero()) {
            // The challenge goes too: it would otherwise outlive the lockout and resume the
            // search where it stopped.
            mfaChallenges.deleteById(challengeKey);
            return new Verification.Throttled(locked);
        }

        if (!totp.verify(user, code)) {
            auth.recordSecondFactorFailure(user.getId());
            // The account-wide ceiling, asked right after counting this failure: the challenge
            // below dies after its own few tries, the account locks after more across challenges,
            // and either one is the moment a guessing attempt stops — which is what a SOC wants.
            boolean accountLocked = !auth.secondFactorLockout(user.getId()).isZero();
            // **The challenge dies on the last try, and that is the control.** Leaving it alive
            // after a wrong code is what turns a six-digit secret into a five-minute exhaustive
            // search: the attacker keeps the same token and keeps going. Counting on the
            // challenge rather than the account also means a wrong guess cannot be used to lock
            // a legitimate user out — the worst it costs them is re-entering their password.
            // Incremented by the database, not read-then-written here: two wrong codes racing
            // would otherwise each read the same count and the challenge would absorb one guess
            // more than it is allowed.
            mfaChallenges.countAttempt(challengeKey);
            boolean exhausted = mfaChallenges
                            .findById(challengeKey)
                            .map(MfaChallengeEntity::getAttempts)
                            .orElse(MAX_MFA_ATTEMPTS)
                    >= MAX_MFA_ATTEMPTS;
            if (exhausted) {
                mfaChallenges.deleteById(challengeKey);
            }

            AuditLogService.Record failure = new AuditLogService.Record(
                    AuditOperation.LOGIN_FAILURE,
                    user.getUsername(),
                    (exhausted
                                    ? "MFA challenge destroyed after " + MAX_MFA_ATTEMPTS
                                            + " invalid verification codes"
                                    : "Invalid MFA verification code attempt")
                            + (accountLocked ? "; second factor locked for this account" : ""),
                    user.getUsername(),
                    ipAddress,
                    userAgent);
            audit.record(exhausted || accountLocked ? failure.signalling(SecurityEventType.MFA_FAILURE_CEILING) : failure);
            return new Verification.WrongCode();
        }

        mfaChallenges.deleteById(challengeKey);
        auth.clearSecondFactorFailures(user.getId());
        AuthService.IssuedSession session =
                auth.openSessionForUser(user, challenge.getUserAgent(), challenge.getIpAddress());

        audit.record(new AuditLogService.Record(
                AuditOperation.LOGIN_SUCCESS,
                user.getUsername(),
                "Signed in with MFA / TOTP: " + user.getUsername(),
                user.getUsername(),
                ipAddress,
                userAgent));

        return new Verification.Verified(session, UserView.of(user));
    }

    /**
     * Stores a challenge, sweeping the ones nobody came back for.
     *
     * <p>An abandoned sign-in — the user closes the tab between the password and the code —
     * leaves an entry that only a later presentation of the same token would remove, and there
     * will not be one. Sweeping on write rather than on a timer keeps the cost proportional to
     * the traffic that creates the entries.
     *
     * <p>The cap after the sweep is the backstop for the case the sweep cannot help with: ten
     * thousand <em>live</em> challenges means something is generating them faster than they
     * expire, and refusing is better than growing.
     *
     * <p><b>In the database, so any instance can answer.</b> This used to be a map on the
     * controller, which made multi-factor sign-in the one feature a documented multi-instance
     * deployment broke: the password is exchanged on one instance and the code arrives on
     * another, which has never heard of the token. The user was told the challenge had expired,
     * a second after it was created, and nothing in the logs distinguished that from a real
     * timeout. Session affinity on {@code /api/v1/auth/**} is no longer required.
     *
     * @return false when the cap refused it, and nothing was stored
     */
    private boolean rememberChallenge(String token, Long userId, Instant expiresAt, String userAgent, String ip) {
        Instant now = clock.instant();
        mfaChallenges.deleteExpired(now);

        if (mfaChallenges.countByExpiresAtAfter(now) >= MAX_MFA_CHALLENGES) {
            return false;
        }

        MfaChallengeEntity challenge = new MfaChallengeEntity();
        challenge.setTokenHash(Sessions.hashOf(token));
        challenge.setUserId(userId);
        challenge.setExpiresAt(expiresAt);
        challenge.setAttempts(0);
        challenge.setUserAgent(userAgent);
        challenge.setIpAddress(ip);
        mfaChallenges.save(challenge);
        return true;
    }

    /** What trading a single sign-on hand-off token came to. */
    public sealed interface Handoff {
        record Expired() implements Handoff {}

        record AccountMissing() implements Handoff {}

        record Exchanged(SessionView session, UserView user) implements Handoff {}
    }

    public Handoff exchange(String token) {
        Optional<SessionView> session = auth.resolve("Bearer " + token);
        if (session.isEmpty()) {
            return new Handoff.Expired();
        }
        return users.findById(session.get().userId())
                .<Handoff>map(user -> new Handoff.Exchanged(session.get(), UserView.of(user)))
                .orElseGet(Handoff.AccountMissing::new);
    }

    /**
     * @param singleSignOn whether an identity provider is wired at all
     * @param label the provider's display name, or null when there is none
     * @param password whether a password may still be exchanged for a session
     */
    public record SignInOptions(boolean singleSignOn, String label, boolean password) {}

    public SignInOptions options() {
        return new SignInOptions(
                providers.isPresent(),
                providers.map(AuthenticationFlowService::labelOf).orElse(null),
                methods.passwordAllowed());
    }

    private static String labelOf(ClientRegistrationRepository repository) {
        if (repository instanceof Iterable<?> registrations) {
            for (Object registration : registrations) {
                if (registration instanceof ClientRegistration client) {
                    return client.getClientName();
                }
            }
        }
        return "single sign-on";
    }

    public enum PasswordChange {
        CHANGED,
        /** The proof of identity failed — not a malformed field, which is refused by exception. */
        CURRENT_PASSWORD_WRONG
    }

    /**
     * Changes one's own password.
     *
     * <p>The current password is required even when {@code mustChangePassword} is set: without
     * it, a workstation left unlocked for a minute would be enough to take the account. There is
     * no "first login" exemption — the person has just typed that password to get here.
     *
     * <p>The account's <b>other</b> sessions are closed. Changing a password is what one does
     * when one believes it compromised: leaving sessions alive elsewhere would empty the gesture
     * of its meaning. The current session survives, or the screen would bounce back to the login
     * page immediately after succeeding.
     *
     * <p>The hash is read here, from the account's row, rather than carried in by the caller: the
     * principal holds a {@link UserView}, which has no password to compare against — deliberately.
     *
     * @throws IllegalArgumentException when the new password breaks a rule, with the rule's text
     * @throws java.util.NoSuchElementException when the account is gone — the bearer filter found it
     *     active at the start of this request, so only a deletion racing it lands here
     */
    public PasswordChange changePassword(
            UserView account,
            Optional<SessionView> currentSession,
            String currentPassword,
            String newPassword,
            String ipAddress,
            String userAgent) {

        UserEntity user = users.findById(account.id()).orElseThrow();
        if (!PasswordHasher.verify(currentPassword, user.getPassword())) {
            return PasswordChange.CURRENT_PASSWORD_WRONG;
        }
        AccountRules.validatePassword(newPassword).ifPresent(message -> {
            throw new IllegalArgumentException(message);
        });
        if (newPassword.equals(currentPassword)) {
            throw new IllegalArgumentException("The new password is the same as the old one.");
        }

        users.changePassword(user.getId(), PasswordHasher.hash(newPassword), clock.instant());
        currentSession.ifPresent(session -> sessions.deleteByUserIdExcept(user.getId(), session.tokenHash()));

        audit.record(new AuditLogService.Record(
                AuditOperation.PASSWORD_CHANGED,
                String.valueOf(user.getId()),
                "Password changed by " + user.getUsername(),
                user.getUsername(),
                ipAddress,
                userAgent));
        return PasswordChange.CHANGED;
    }
}
