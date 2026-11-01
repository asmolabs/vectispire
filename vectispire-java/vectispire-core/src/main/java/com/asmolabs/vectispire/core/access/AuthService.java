package com.asmolabs.vectispire.core.access;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.auth.LoginThrottle;
import com.asmolabs.vectispire.common.domain.auth.Sessions;
import com.asmolabs.vectispire.common.domain.crypto.PasswordHasher;
import com.asmolabs.vectispire.common.domain.siem.SecurityEventType;
import com.asmolabs.vectispire.common.domain.text.BoundedText;
import com.asmolabs.vectispire.common.domain.users.AccountRules;
import com.asmolabs.vectispire.core.access.persistence.LoginAttemptEntity;
import com.asmolabs.vectispire.core.access.persistence.LoginAttemptRepository;
import com.asmolabs.vectispire.core.access.persistence.SessionEntity;
import com.asmolabs.vectispire.core.access.persistence.UserEntity;
import com.asmolabs.vectispire.core.access.persistence.SessionRepository;
import com.asmolabs.vectispire.core.access.persistence.SignInClientEntity;
import com.asmolabs.vectispire.core.access.persistence.SignInClientRepository;
import com.asmolabs.vectispire.core.access.persistence.UserRepository;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionOperations;
import org.springframework.transaction.support.TransactionTemplate;

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

    private final UserRepository users;
    private final SessionRepository sessions;
    private final LoginAttemptRepository attempts;
    private final SignInClientRepository knownClients;
    private final SignInLimits limits;
    private final Sessions.Policy policy;
    private final Clock clock;

    /**
     * When each spent budget was last warned about, so a guess spread over a thousand addresses is one
     * warning a window in the log rather than one per refusal — each refusal still has its audit entry.
     * In memory, and bounded: a restart, or an attacker cycling through names, costs a warning repeated,
     * never one lost.
     */
    private final Map<String, Instant> warned = new ConcurrentHashMap<>();

    /** Each step of a {@link #reserve reservation} commits on its own — see there. */
    private final TransactionOperations separately;

    @Autowired
    public AuthService(
            UserRepository users,
            SessionRepository sessions,
            LoginAttemptRepository attempts,
            SignInClientRepository knownClients,
            SignInLimits limits,
            Sessions.Policy policy,
            Clock clock,
            PlatformTransactionManager transactions) {
        this(users, sessions, attempts, knownClients, limits, policy, clock, requiresNew(transactions));
    }

    /** With the boundary supplied — {@link TransactionOperations#withoutTransaction()} for a unit test. */
    public AuthService(
            UserRepository users,
            SessionRepository sessions,
            LoginAttemptRepository attempts,
            SignInClientRepository knownClients,
            SignInLimits limits,
            Sessions.Policy policy,
            Clock clock,
            TransactionOperations separately) {
        this.users = users;
        this.sessions = sessions;
        this.attempts = attempts;
        this.knownClients = knownClients;
        this.limits = limits;
        this.policy = policy;
        this.clock = clock;
        this.separately = separately;
    }

    private static TransactionTemplate requiresNew(PlatformTransactionManager transactions) {
        TransactionTemplate template = new TransactionTemplate(transactions);
        template.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        return template;
    }

    /**
     * An attempt counted before it is checked.
     *
     * <p><b>Why a failure is written before the verification it may turn out to be.</b> The
     * counters used to be read, then the secret verified, then a failure written: two attempts
     * arriving together both read four failures, both were admitted, and a ceiling of five let
     * through as many guesses as the attacker could send at once — an Argon2 derivation or a TOTP
     * check is a long window. Now each attempt writes its row and commits, <em>then</em> counts:
     * whichever commits k-th sees the k-1 before it, so at most the ceiling are admitted however
     * many arrive together. A refused attempt takes its row back, so being refused does not extend
     * the lockout; an admitted one keeps it as its failure, and a success clears the counter.
     *
     * <p><b>The cost, accepted:</b> attempts that arrive together may all be refused, each counting
     * the others' rows before they are taken back — MySQL showed a burst of sixteen refused whole.
     * The ceiling is never exceeded; a burst against one account is refused more readily than a
     * sequence, which is the right way round for a throttle.
     *
     * @param rows this attempt's own rows, which a success or a refusal removes
     * @param retryAfter zero when admitted
     * @param budgetRetryAfter the soft ceilings' verdict, which {@link #retryAfter} leaves out: zero
     *     when the account's budget across clients is not spent. What it refuses is the caller's to
     *     decide — see {@link #login}.
     */
    public record Reservation(Set<UUID> rows, Duration retryAfter, Duration budgetRetryAfter) {

        public Reservation(Set<UUID> rows, Duration retryAfter) {
            this(rows, retryAfter, Duration.ZERO);
        }

        public boolean admitted() {
            return retryAfter.isZero();
        }
    }

    /**
     * Writes one failure per counter, commits, then decides against each ceiling — the strictest
     * wins. See {@link Reservation}.
     *
     * <p>In transactions of its own, whatever the caller holds: a row still uncommitted when a
     * concurrent attempt counts is a row that attempt does not see, which is the race itself.
     */
    public Reservation reserve(Map<String, Integer> ceilings) {
        return reserve(ceilings, Set.of());
    }

    /**
     * The same, with some ceilings soft: their verdict is {@link Reservation#budgetRetryAfter} and not
     * a refusal, and their rows are written and counted like any other.
     */
    public Reservation reserve(Map<String, Integer> ceilings, Set<String> soft) {
        Instant now = clock.instant();
        List<LoginAttemptEntity> mine = separately.execute(status -> {
            List<LoginAttemptEntity> written = new ArrayList<>();
            ceilings.keySet().forEach(key -> written.add(attempts.save(attempt(key, now))));
            return written;
        });
        Set<UUID> own = mine.stream().map(LoginAttemptEntity::getId).filter(Objects::nonNull).collect(Collectors.toSet());

        Duration wait = Duration.ZERO;
        Duration budget = Duration.ZERO;
        for (Map.Entry<String, Integer> ceiling : ceilings.entrySet()) {
            List<Instant> others = separately.execute(status -> attempts
                    .findByCounterKeyAndOccurredAtAfter(ceiling.getKey(), now.minus(LoginThrottle.WINDOW)).stream()
                    .filter(row -> row.getId() == null || !own.contains(row.getId()))
                    .map(LoginAttemptEntity::getOccurredAt)
                    .toList());
            Duration retryAfter = LoginThrottle.decide(others, ceiling.getValue(), now).retryAfter();
            if (soft.contains(ceiling.getKey())) {
                budget = retryAfter.compareTo(budget) > 0 ? retryAfter : budget;
            } else if (retryAfter.compareTo(wait) > 0) {
                wait = retryAfter;
            }
        }

        Reservation reservation = new Reservation(own, wait, budget);
        if (!reservation.admitted()) {
            release(reservation);
        }
        return reservation;
    }

    /** Takes a reservation's rows back — a refused attempt, or one whose outcome is not a failure. */
    public void release(Reservation reservation) {
        if (!reservation.rows().isEmpty()) {
            separately.executeWithoutResult(status -> attempts.deleteByIdIn(reservation.rows()));
        }
    }

    /**
     * A second-factor attempt, against the account's budget of wrong codes — see
     * {@link LoginThrottle#MAX_SECOND_FACTOR_FAILURES}.
     */
    public Reservation reserveSecondFactor(long accountId) {
        return reserve(Map.of(LoginThrottle.secondFactorKey(accountId), LoginThrottle.MAX_SECOND_FACTOR_FAILURES));
    }

    /**
     * A password presented by a signed-in account — changing its own — against the budget of the
     * sign-in form from the same client, and the account's global one. A session is not a licence
     * to guess the password behind it: a workstation left unlocked would otherwise be a password
     * oracle with no ceiling.
     */
    public Reservation reservePassword(long accountId, String ipAddress) {
        String everywhere = LoginThrottle.accountKey(accountId);
        Reservation reservation = reserve(
                Map.of(
                        LoginThrottle.accountKey(accountId, ipAddress), limits.failuresPerAccountFromClient(),
                        everywhere, limits.failuresPerAccount()),
                Set.of(everywhere));
        // The account's budget across clients is soft here as at sign-in, by the same rule: a session
        // is no exemption of its own — it may be a stolen one, used from anywhere — but the client the
        // owner signs in from is.
        if (reservation.admitted() && !reservation.budgetRetryAfter().isZero() && !isKnownClient(accountId, ipAddress)) {
            release(reservation);
            return new Reservation(Set.of(), reservation.budgetRetryAfter());
        }
        return reservation;
    }

    /**
     * A right password: the account's counter from this client starts again, as a sign-in's does.
     * The global one keeps the other clients' failures — see {@link #login}.
     */
    public void clearPasswordFailures(long accountId, String ipAddress) {
        attempts.deleteByCounterKey(LoginThrottle.accountKey(accountId, ipAddress));
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

    /**
     * The second factor sent with the password, which carries a sign-in past the account's spent
     * budget across clients — see {@link #login}. Supplied by {@code AuthenticationFlowService}, which
     * owns the codes; asked only once the password is right, so only someone who holds it spends the
     * account's budget of wrong codes, as on a challenge.
     */
    @FunctionalInterface
    public interface SecondFactor {
        /** Whether the code is the account's, counting a wrong one against its budget of codes. */
        boolean verifies(UserEntity account);
    }

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

        /**
         * Refused by the account's budget across every client — {@code account-throttled}, and not the
         * same code as {@link Blocked}: the remedy is not to wait but to sign in from a usual place, or
         * with the second factor. It says nothing about the password, which may not have been tried.
         */
        record AccountThrottled(Duration retryAfter) implements Outcome {}
    }

    /**
     * A session that has just been opened: the row, and the token the client must be given.
     *
     * <p>The two travel together for the length of one request and then part: the token goes out
     * over HTTPS and is forgotten, the row stays with only its hash. Any caller that needs to
     * *identify* the session later — to revoke it, or to spare it — uses
     * {@link SessionView#tokenHash()}; only a caller handing the session to its owner uses
     * {@link #token()}.
     */
    public record IssuedSession(SessionView session, String token) {}

    /**
     * @param audit returned rather than written here, so this service does not depend on the
     *     audit log and stays testable alone
     */
    public record LoginResult(Outcome outcome, AuditLogService.Record audit) {}

    /**
     * Not {@code @Transactional}, deliberately: the attempt is {@link #reserve reserved} in
     * transactions of its own before the password is verified, and every write after it — the
     * session, a rehash, clearing the counters — is a repository call that commits by itself.
     */
    public LoginResult login(LoginRequest request) {
        return login(request, Optional.empty());
    }

    /**
     * @param secondFactor the code sent with the password, if any. Read only when the account's budget
     *     across clients is spent and this client is not known to the account; otherwise the code is
     *     asked for afterwards, by the challenge, as it always was.
     */
    public LoginResult login(LoginRequest request, Optional<SecondFactor> secondFactor) {
        Instant now = clock.instant();
        // Looked up before the throttle, which costs a query and no hashing. The account is
        // what the counter protects, and the username the caller typed is not the account: the
        // lookup follows the database's collation, which on MySQL ignores case and accents, so
        // "Alice", "alice" and "Àlice" were three counters opening one account — five tries each.
        // The folded name is counted as well, for an existing account and an unknown one alike,
        // and the stricter of the two decides: which counters an attempt meets must not depend on
        // whether the account exists — see LoginThrottle#userKey.
        //
        // **A name no account can hold opens no account.** The collation also ignores characters an
        // account name never contains — U+00AD, U+200B to U+200D, U+2060, U+FEFF, controls — so
        // "ali\u00ADce" opened "alice" and met its account counter, while its folded key was a counter
        // of its own: the sixth attempt answered 429 when the account existed and 401 when it did not.
        // Every account is created under AccountRules' grammar; a typed name outside it is answered as
        // an unknown one — counted on its name key, verified against the stand-in hash, refused alike.
        Optional<UserEntity> user = AccountRules.isWellFormedUsername(request.username())
                ? users.findByUsername(request.username())
                : Optional.empty();
        //
        // **The low ceiling is the account's from this client, not the account's.** One counter
        // shared by every client let anyone who knew a name keep that account locked — five wrong
        // passwords a quarter of an hour, the governor's included — and the owner's right password
        // was refused with the rest. Each counter is kept twice: from this client at the low
        // ceiling, and from everywhere at one ten times higher, against guessing spread across
        // machines. See LoginThrottle.
        String ipAddress = String.valueOf(request.ipAddress());
        String clientKey = LoginThrottle.clientKey(ipAddress);
        //
        // **The ceiling from everywhere is a budget, not a lock.** It was a hard ceiling, and the
        // owner's right password was refused with the guesser's once fifty failures had come from
        // anywhere: whoever knew a name and had ten addresses kept that account shut. It is soft now
        // (`soft` below), and what it refuses is decided after the reservation:
        //
        //  - a client known to the account — one that signed in to it within the retention, see
        //    LoginThrottle#knownClientKey — goes on to the password, held to this client's own
        //    ceilings only. The owner at their usual place is not stopped by a guess made elsewhere.
        //  - any other client is answered `account-throttled`, before any hashing, its rows taken
        //    back so the refusal extends nothing — unless it sent the second factor with the password.
        //    Then both are verified and the answer is a session, or the same refusal whatever was
        //    wrong: a guesser past the budget learns nothing from the password, right or wrong, and
        //    the owner with their phone gets in from anywhere.
        //
        // Which is uniform across names: an unknown name has no known client, so past the budget its
        // attempt meets the same refusal an existing account's does from a new place.
        Map<String, Integer> ceilings = new LinkedHashMap<>();
        Set<String> fromThisClient = new java.util.HashSet<>();
        Set<String> everywhere = new java.util.HashSet<>();
        user.ifPresent(found -> {
            ceilings.put(LoginThrottle.accountKey(found.getId(), ipAddress), limits.failuresPerAccountFromClient());
            ceilings.put(LoginThrottle.accountKey(found.getId()), limits.failuresPerAccount());
            fromThisClient.add(LoginThrottle.accountKey(found.getId(), ipAddress));
            everywhere.add(LoginThrottle.accountKey(found.getId()));
        });
        ceilings.put(LoginThrottle.userKey(request.username(), ipAddress), limits.failuresPerAccountFromClient());
        ceilings.put(LoginThrottle.userKey(request.username()), limits.failuresPerAccount());
        fromThisClient.add(LoginThrottle.userKey(request.username(), ipAddress));
        everywhere.add(LoginThrottle.userKey(request.username()));
        ceilings.put(clientKey, limits.failuresPerClient());

        Reservation throttle = reserve(ceilings, everywhere);

        if (!throttle.admitted()) {
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

        boolean overBudget = !throttle.budgetRetryAfter().isZero()
                && user.map(found -> !isKnownClient(found.getId(), ipAddress)).orElse(true);
        if (overBudget && secondFactor.isEmpty()) {
            release(throttle);
            return accountThrottled(request, user, throttle.budgetRetryAfter());
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

        // Past the budget, a right password is not enough and is answered as a wrong one is — the rows
        // stay, nothing is cleared — or the refusal would say which passwords were right. Only the code
        // the owner sent with it, verified now that the password is known to be theirs, opens the way.
        if (overBudget && !(authenticated
                && user.orElseThrow().getMfaEnabled()
                && secondFactor.orElseThrow().verifies(user.orElseThrow()))) {
            return accountThrottled(request, user, throttle.budgetRetryAfter());
        }

        if (!authenticated) {
            // The reservation's rows stay: they are this failure.
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

        // **A success clears what it proves, and only that.** Every counter of the attempt used to
        // be emptied, the address's included: one sign-in to one's own account every nineteen tries
        // wiped the address's record of the other nineteen, and the ceiling meant to slow one
        // password tried across many names slowed nothing. The account and the name typed start
        // again from this client — five mistypes then the right password is not an attack on
        // them — while the address and the account's global counter keep their failures, which
        // other clients may have made; this attempt's own rows are taken back, since a success is
        // not a failure.
        release(throttle);
        fromThisClient.forEach(attempts::deleteByCounterKey);

        UserEntity found = user.orElseThrow();
        rehashIfStale(found, request.password());
        // Past the budget the code has just been verified: asking for it again would be a challenge
        // the owner already answered.
        if (found.getMfaEnabled() && !overBudget) {
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
                        AuditOperation.LOGIN_SUCCESS,
                        found.getUsername(),
                        overBudget
                                ? "Login succeeded with password and second factor, past the account's spent budget"
                                : "Login succeeded",
                        found.getUsername()));
    }

    /**
     * A refusal by the account's budget across clients: its audit entry, signalled as every throttle's
     * is, and a warning in the log once a window per budget — the operator's first sign that an
     * account is being guessed at from many places, which no single address's ceiling shows.
     */
    private LoginResult accountThrottled(LoginRequest request, Optional<UserEntity> user, Duration retryAfter) {
        String budget = user.map(found -> LoginThrottle.accountKey(found.getId()))
                .orElseGet(() -> LoginThrottle.userKey(request.username()));
        Instant now = clock.instant();
        Instant last = warned.get(budget);
        if (last == null || !last.plus(LoginThrottle.WINDOW).isAfter(now)) {
            if (warned.size() >= 10_000) {
                warned.clear();
            }
            warned.put(budget, now);
            // The account's id, or no name at all: the typed name is the caller's text, and an unknown
            // one has no business in the operator's log beyond the audit entry that already holds it.
            log.warn("Sign-in budget across clients spent for {}: attempts from clients that have not signed in to it "
                            + "are refused for {}s. Several addresses are guessing its password.",
                    user.map(found -> "account " + found.getId()).orElse("a name no account holds"),
                    retryAfter.toSeconds());
        }
        return new LoginResult(
                new Outcome.AccountThrottled(retryAfter),
                AuditLogService.Record.of(
                                AuditOperation.LOGIN_BLOCKED,
                                request.username(),
                                "Attempt refused: the account's sign-in budget across clients is spent ("
                                        + retryAfter.toSeconds() + "s to wait)",
                                request.username())
                        .signalling(SecurityEventType.SIGN_IN_THROTTLED));
    }

    /** Whether this client has signed in to the account within the retention — see {@link #login}. */
    private boolean isKnownClient(long accountId, String ipAddress) {
        if (ipAddress == null) {
            return false;
        }
        return separately.execute(status -> knownClients.existsByClientKeyAndLastSignedInAtAfter(
                LoginThrottle.knownClientKey(accountId, ipAddress),
                clock.instant().minus(limits.knownClientRetention())));
    }

    /**
     * Remembers the client a session was opened for, in a transaction of its own and never failing the
     * sign-in: a sign-in that succeeded is not refused over the record that makes the next one easier,
     * and a concurrent sign-in inserting the same key first is the same record.
     */
    private void rememberClient(long accountId, String ipAddress, Instant now) {
        if (ipAddress == null) {
            return;
        }
        String key = LoginThrottle.knownClientKey(accountId, ipAddress);
        try {
            separately.executeWithoutResult(status -> {
                if (knownClients.touch(key, now) == 0) {
                    SignInClientEntity known = new SignInClientEntity();
                    known.setClientKey(key);
                    known.setAccountId(accountId);
                    known.setLastSignedInAt(now);
                    knownClients.save(known);
                }
            });
        } catch (RuntimeException couldNotRecord) {
            log.debug("Could not record the client of account {}: {}", accountId, couldNotRecord.getMessage());
        }
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
    public Optional<UserView> activeUserOf(SessionView session) {
        return users.findById(session.userId()).filter(UserEntity::getIsActive).map(UserView::of);
    }

    /**
     * An account by its id, if it may still act — for a gesture asked now and carried out later, read again
     * when it is carried out: a report run builds its export for its requester at the claim (decision 0035
     * §2), and an account deactivated in between has nobody's export built for it.
     */
    @Transactional(readOnly = true)
    public Optional<UserView> activeAccount(long accountId) {
        return users.findById(accountId).filter(UserEntity::getIsActive).map(UserView::of);
    }

    /**
     * Resolves a token into an active session, refreshing its activity timestamp.
     *
     * <p>An expired session is <b>deleted</b> rather than merely refused: leaving it would grow
     * the table with rows that will never serve again, and the scheduler's purge would be left
     * collecting what nobody touched.
     */
    @Transactional
    public Optional<SessionView> resolve(String authorizationHeader) {
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
            return Optional.of(SessionView.of(session));
        }

        session.setLastSeenAt(now);
        return Optional.of(SessionView.of(sessions.save(session)));
    }

    /**
     * A real logout: the row disappears and the token is worth nothing.
     *
     * <p>Takes the resolved session rather than the token because that is what every caller has —
     * the bearer filter and the logout route both hold one — and because a
     * {@code revoke(String)} would accept either the token or its hash, one of which silently
     * revokes nothing.
     */
    @Transactional
    public void revoke(SessionView session) {
        sessions.deleteById(session.tokenHash());
    }

    /**
     * The hand-off a single sign-on left, if it is still waiting — see {@link Sessions#handoffHashOf}.
     *
     * <p>Its lifetime is the cookie's, enforced here: a cookie the browser kept, or a value copied
     * out of a log, is worth nothing after it.
     */
    @Transactional
    public Optional<SessionView> resolveHandoff(String token) {
        if (token == null || token.isBlank()) {
            return Optional.empty();
        }
        Optional<SessionEntity> found = sessions.findById(Sessions.handoffHashOf(token));
        if (found.isEmpty()) {
            return Optional.empty();
        }
        if (found.get().getCreatedAt().plus(Sessions.HANDOFF_LIFETIME).isBefore(clock.instant())) {
            sessions.deleteById(found.get().getTokenHash());
            return Optional.empty();
        }
        return Optional.of(SessionView.of(found.get()));
    }

    /**
     * Trades a session for a fresh one of the same account, once.
     *
     * <p>The single sign-on hand-off: the cookie the provider's redirect left carries a session
     * token, and the exchange used to hand that same token back — as many times as the cookie was
     * presented, for its whole lifetime. Now the hand-off session is deleted and a new one opened;
     * the delete's row count decides, so of two exchanges of one cookie only one gets a session.
     *
     * @return empty when the session was already consumed
     */
    @Transactional
    public Optional<IssuedSession> exchangeOnce(SessionView handoff) {
        if (sessions.consume(handoff.tokenHash()) != 1) {
            return Optional.empty();
        }
        return Optional.of(openSession(handoff.userId(),
                new LoginRequest(null, null, handoff.userAgent(), handoff.ipAddress()), clock.instant()));
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

    /**
     * The hand-off of a single sign-on: a row the redirect's cookie names, exchanged once for a
     * session by {@link #exchangeOnce} and usable for nothing else — stored under
     * {@link Sessions#handoffHashOf}, which the bearer route never computes, and expiring with the
     * cookie.
     */
    @Transactional
    public IssuedSession openHandoff(UserView user, String userAgent, String ipAddress) {
        Instant now = clock.instant();
        Sessions.IssuedToken minted = Sessions.issue();
        SessionEntity session = new SessionEntity();
        session.setTokenHash(Sessions.handoffHashOf(minted.token()));
        session.setUserId(user.id());
        session.setCreatedAt(now);
        session.setLastSeenAt(now);
        session.setExpiresAt(now.plus(Sessions.HANDOFF_LIFETIME));
        session.setUserAgent(clip(userAgent));
        session.setIpAddress(ipAddress);
        return new IssuedSession(SessionView.of(sessions.save(session)), minted.token());
    }

    private IssuedSession openSession(UserEntity user, LoginRequest request, Instant now) {
        return openSession(user.getId(), request, now);
    }

    private IssuedSession openSession(Long userId, LoginRequest request, Instant now) {
        Sessions.IssuedToken minted = Sessions.issue();
        SessionEntity session = new SessionEntity();
        session.setTokenHash(minted.hash());
        session.setUserId(userId);
        session.setCreatedAt(now);
        session.setLastSeenAt(now);
        session.setExpiresAt(now.plus(policy.absoluteLifetime()));
        session.setUserAgent(clip(request.userAgent()));
        session.setIpAddress(request.ipAddress());
        IssuedSession issued = new IssuedSession(SessionView.of(sessions.save(session)), minted.token());
        rememberClient(userId, request.ipAddress(), now);
        return issued;
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

    private static LoginAttemptEntity attempt(String counterKey, Instant now) {
        LoginAttemptEntity attempt = new LoginAttemptEntity();
        attempt.setCounterKey(counterKey);
        attempt.setOccurredAt(now);
        return attempt;
    }

    /**
     * A User-Agent cut to its column, on a character boundary: a {@code substring} could leave half
     * a surrogate pair, which is no character in any encoding.
     */
    static String clip(String value) {
        return BoundedText.clip(value, 255);
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
