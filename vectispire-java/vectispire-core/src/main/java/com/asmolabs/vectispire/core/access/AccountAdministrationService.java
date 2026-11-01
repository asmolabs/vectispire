package com.asmolabs.vectispire.core.access;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.crypto.PasswordHasher;
import com.asmolabs.vectispire.common.domain.errors.ConflictException;
import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.common.domain.errors.NotFoundException;
import com.asmolabs.vectispire.common.domain.paging.ListWindow;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.text.BoundedText;
import com.asmolabs.vectispire.common.domain.users.AccountGesture;
import com.asmolabs.vectispire.common.domain.users.AccountRules;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.access.internal.AccountAdminService;
import com.asmolabs.vectispire.core.access.internal.GrantTargets;
import com.asmolabs.vectispire.core.access.persistence.AccountRequestEntity;
import com.asmolabs.vectispire.core.access.persistence.AccountRequestRepository;
import com.asmolabs.vectispire.core.access.persistence.SessionRepository;
import com.asmolabs.vectispire.core.access.persistence.UserEntity;
import com.asmolabs.vectispire.core.access.persistence.UserRepository;
import com.asmolabs.vectispire.core.access.persistence.UserTargetEntity;
import com.asmolabs.vectispire.core.access.persistence.UserTargetRepository;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.audit.RequestActor;
import com.asmolabs.vectispire.core.settings.SettingsService;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * An administrator managing other people's accounts: the guard rails, the audit trail, and what
 * each gesture revokes.
 *
 * <p><b>Beside {@link AccountAdminService}, not merged into it.</b> That class exists for its
 * transaction boundaries and says so; the rules here — who may be demoted, which change closes
 * the sessions — decide <em>what</em> to write, and call it to write it atomically. The audit
 * entry is written here, after it returns, for the reason that class gives: an audited action
 * that rolls back is still recorded as attempted only if its entry is outside the boundary.
 *
 * <p>Every refusal is an {@link InvalidInputException} carrying text meant for the screen, and
 * every missing account a {@link NotFoundException} — the 400 and the 404 the handler maps.
 *
 * <p><b>Under four-eyes, a change that makes an approver waits for a second administrator</b> (#126,
 * option 2): creating an account with a role that {@link Role#approves() approves}, giving such a role,
 * and resetting the password of an account that holds one are filed as an account request rather than
 * applied, and {@link AccountRequestService} applies them once another administrator approves. Every
 * other gesture — activation, targets, a role that approves nothing — applies at once, as it always did:
 * taking a privilege away must stay easy. The request is checked as the change would be when it is filed,
 * so the requester hears a refusal now rather than the approver later, and again with the approver as the
 * acting account when it is applied.
 *
 * <p><b>Who administered whom is recorded beside the change</b> ({@link ApproverIndependence}), in the
 * transaction that writes it: creating an account, resetting its password and changing its role each
 * leave a row naming the administrator, which an approval under four-eyes reads.
 */
@Service
public class AccountAdministrationService {

    /** The width of {@code email} and {@code display_name}. */
    private static final int BOUNDED_COLUMN = 255;

    private final UserRepository users;
    private final SessionRepository sessions;
    private final UserTargetRepository assignments;
    private final AccountAdminService accounts;
    private final AuditLogService audit;
    private final Clock clock;
    private final GrantTargets grantTargets;
    private final GrantableTargets targets;
    private final AccountRequestRepository requests;
    private final ApproverIndependence independence;
    private final SettingsService settings;
    private final TransactionTemplate transaction;

    public AccountAdministrationService(
            UserRepository users,
            SessionRepository sessions,
            UserTargetRepository assignments,
            AccountAdminService accounts,
            AuditLogService audit,
            Clock clock,
            GrantTargets grantTargets,
            GrantableTargets targets,
            AccountRequestRepository requests,
            ApproverIndependence independence,
            SettingsService settings,
            PlatformTransactionManager transactionManager) {
        this.users = users;
        this.sessions = sessions;
        this.assignments = assignments;
        this.accounts = accounts;
        this.audit = audit;
        this.clock = clock;
        this.grantTargets = grantTargets;
        this.targets = targets;
        this.requests = requests;
        this.independence = independence;
        this.settings = settings;
        this.transaction = new TransactionTemplate(transactionManager);
    }

    /** An account and how many live sessions it holds. */
    public record AccountView(UserView user, long activeSessions) {}

    /** @param kind {@code repository}, {@code container} or {@code project} */
    public record TargetAssignment(String kind, Long id) implements GrantableTargets.Grant {

        /** By kind, then id: the primary key's order after the owner's column. */
        static final Comparator<TargetAssignment> ORDER =
                Comparator.comparing(TargetAssignment::kind).thenComparing(TargetAssignment::id);
    }

    public record NewAccount(String username, String password, String role, String email, String displayName) {}

    /** Every field optional: absent means "leave it as it is". */
    public record AccountChange(String role, Boolean isActive, String password) {}

    /**
     * What became of a creation or a change: applied, or filed for a second administrator.
     *
     * <p>A type with two cases rather than an account that may or may not have changed: a caller that
     * reads an account from a request still waiting would show a change nobody has made.
     */
    public sealed interface Outcome {

        /** Applied: the account as it now stands. */
        record Applied(AccountView account) implements Outcome {}

        /** Filed under four-eyes; nothing has changed yet. */
        record Queued(AccountRequestView request) implements Outcome {}
    }

    /** A change written, and the audit entries to record once its transaction has committed. */
    record Written(AccountView account, List<AuditLogService.Record> entries) {}

    /** A role request whose wire name is {@code create}. */
    static final String CREATE = "create";

    /** A role or password request on an existing account. */
    static final String CHANGE = "change";

    static final String PENDING = "pending";


    /**
     * The accounts on one page of the administration list, and how many there are on every page.
     *
     * @param total the accounts the list holds, whether or not the page shows them all
     */
    public record Accounts(List<AccountView> accounts, long total) {}

    /**
     * The accounts by username — unique, so the order a page is cut from — all of them or one page.
     *
     * @param limit rows per page, or null for every account ({@link ListWindow#requested})
     * @throws InvalidInputException a window the rule refuses
     */
    public Accounts list(Integer limit, Integer offset) {
        Optional<ListWindow> window = ListWindow.requested(limit, offset);
        Map<Long, Long> active = activeSessionsByUser();
        List<UserEntity> every = users.findAllByOrderByUsernameAsc();
        List<AccountView> views = new ArrayList<>();
        window.map(page -> page.of(every)).orElse(every)
                .forEach(user -> views.add(new AccountView(UserView.of(user), active.getOrDefault(user.getId(), 0L))));
        return new Accounts(views, every.size());
    }

    /**
     * Creates an account — or, under four-eyes, files the creation of one with an approving role for a second
     * administrator.
     *
     * @param actingAccountId the account creating it, or null for a caller that is not one — who
     *     may grant the platform governor role depends on it
     */
    public Outcome create(NewAccount request, Long actingAccountId, RequestActor actor) {
        String username = trim(request.username());
        String password = request.password() == null ? "" : request.password();
        String role = trim(request.role()).isEmpty() ? Role.USER.name() : trim(request.role()).toUpperCase(Locale.ROOT);

        refuseIfInvalid(AccountRules.validateUsername(username));
        refuseIfInvalid(AccountRules.validatePassword(password));
        NewAccount normalized = new NewAccount(username, null, role, request.email(), request.displayName());
        refuseInvalidCreation(normalized, actingAccountId);

        if (needsSecondAdministrator(actingAccountId, Role.of(role).orElseThrow())) {
            AccountRequestEntity filed = new AccountRequestEntity();
            filed.setKind(CREATE);
            filed.setUsername(username);
            filed.setEmail(BoundedText.optional(request.email(), BOUNDED_COLUMN, "The e-mail address"));
            filed.setDisplayName(BoundedText.optional(request.displayName(), BOUNDED_COLUMN, "The display name"));
            filed.setRequestedRole(role);
            filed.setPasswordHash(PasswordHasher.hash(password));
            return file(filed, actingAccountId, actor,
                    "Account creation requested: " + username + " (" + role + ")");
        }

        String hash = PasswordHasher.hash(password);
        String alone = appliedAlone(actingAccountId, Role.of(role).orElseThrow());
        Written written = transaction.execute(status -> writeCreation(
                normalized, hash, actingAccountId, actingAccountId == null ? List.of() : List.of(actingAccountId), alone, actor));
        written.entries().forEach(audit::record);
        return new Outcome.Applied(written.account());
    }

    /**
     * The rules a creation is held to when it is asked for and again when it is applied — with the
     * approver as the acting account then, since who may grant the governor role depends on who grants it.
     *
     * @param request trimmed, its role upper-cased; its password is checked by the caller, which may hold a hash
     */
    void refuseInvalidCreation(NewAccount request, Long actingAccountId) {
        refuseIfInvalid(AccountRules.validateUsername(request.username()));
        if (Role.of(request.role()).isEmpty()) {
            throw new InvalidInputException("Unknown role: " + request.role() + ".");
        }
        refuseGovernorAdministration(actingAccountId, Optional.empty(), Role.of(request.role()));
        if (users.findByUsername(request.username()).isPresent()) {
            throw new InvalidInputException("The username \"" + request.username() + "\" is already taken.");
        }
    }

    /**
     * Writes a new account and who made it; in the caller's transaction.
     *
     * @param administrators every account behind the creation, for {@link ApproverIndependence}
     * @param provenance appended to the audit sentence: empty, or who asked for and approved it
     */
    Written writeCreation(NewAccount request, String passwordHash, Long actingAccountId, List<Long> administrators,
            String provenance, RequestActor actor) {
        refuseInvalidCreation(request, actingAccountId);
        Instant createdAt = clock.instant();
        UserEntity user = new UserEntity();
        user.setUsername(request.username());
        // Bounded like every column a form writes: past 255 the database refused the row at the
        // write, and the administrator got a 500 for a pasted signature block.
        user.setEmail(BoundedText.optional(request.email(), BOUNDED_COLUMN, "The e-mail address"));
        user.setDisplayName(BoundedText.optional(request.displayName(), BOUNDED_COLUMN, "The display name"));
        user.setPassword(passwordHash);
        user.setRole(request.role());
        user.setIsActive(true);
        // The password set here is known to the administrator who typed it: it is a pass, not
        // the account's secret.
        user.setMustChangePassword(true);
        user.setCreatedAt(createdAt);
        user.setUpdatedAt(createdAt);

        UserEntity saved = users.save(user);
        independence.recorded(saved.getId(), null, administrators, List.of(AccountGesture.CREATED), createdAt);
        return new Written(new AccountView(UserView.of(saved), 0), List.of(entry(
                actor, saved.getId(), "Account created: " + request.username() + " (" + request.role() + ")" + provenance)));
    }

    /**
     * Role, activation and password reset — or, under four-eyes, the role or the password filed for a second
     * administrator when the change makes an approver.
     *
     * <p>The three carry the same guard rails, so there is one entry point rather than three to
     * keep in step.
     *
     * <p><b>Activation is never held back.</b> A change filed for approval that also activates or
     * deactivates the account applies that part at once: deactivating is how an administrator stops an
     * account, and a stop that waits for a second person is no stop.
     *
     * @param actingAccountId the account making the change, or null for a caller that is not one —
     *     used to recognise a change to one's own account. Apart from the audit identity, because
     *     only this service needs it
     */
    public Outcome update(long id, AccountChange change, Long actingAccountId, RequestActor actor) {
        UserEntity user = requireAccount(id);

        String role = change.role() == null ? user.getRole() : trim(change.role()).toUpperCase(Locale.ROOT);
        String password = change.password();

        if (Role.of(role).isEmpty()) {
            throw new InvalidInputException("Unknown role: " + role + ".");
        }
        if (password != null) {
            refuseIfInvalid(AccountRules.validatePassword(password));
        }

        boolean roleChanges = !role.equals(user.getRole());
        // A reset waits for the pending change to be decided first: applied at once beside a pending raise, it
        // would hand whoever typed the password the role the raise grants, under an approval that did not show
        // it. Lowering the role stays possible, and makes the pending raise stale.
        if (password != null && requests.existsByStatusAndAccountId(PENDING, id)) {
            throw new ConflictException("A change to " + user.getUsername()
                    + " is already waiting for approval: have it approved or rejected first.");
        }
        boolean makesAnApprover = (roleChanges && Role.of(role).orElseThrow().approves())
                || (password != null && (approves(user.getRole()) || approves(role)));
        if (!makesAnApprover || !needsSecondAdministrator(actingAccountId, Role.of(role).orElseThrow())) {
            String alone = makesAnApprover ? appliedAlone(actingAccountId, Role.of(role).orElseThrow()) : "";
            Written written = transaction.execute(status -> writeChange(
                    id, change.role() == null ? null : role, change.isActive(),
                    password == null ? null : PasswordHasher.hash(password),
                    actingAccountId, actingAccountId == null ? List.of() : List.of(actingAccountId), alone, actor));
            written.entries().forEach(audit::record);
            return new Outcome.Applied(written.account());
        }

        // Checked now, with the requester acting, so that a change the rules refuse is refused to the person
        // asking rather than filed and refused to the approver; checked again when it is applied.
        refuseInvalidChange(user, role, change.isActive() == null ? user.getIsActive() : change.isActive(), actingAccountId);
        UserEntity requester = requireAccount(actingAccountId);
        if (roleChanges && Role.of(role).orElseThrow().approves()) {
            // Refused now rather than at the approval: the requester who created this account or typed its
            // password may know it, and the raise would hand them an approver (lower, reset, raise).
            independence.requirePasswordUnknown(id, user.getUsername(), requester.getId(), requester.getUsername());
        }
        // Refused before the activation below is applied, so a refusal leaves nothing half done; the filing
        // checks again under the account's lock.
        if (requests.existsByStatusAndAccountId(PENDING, id)) {
            throw new ConflictException("A change to " + user.getUsername()
                    + " is already waiting for approval: have it approved or rejected first.");
        }
        if (change.isActive() != null && change.isActive() != user.getIsActive()) {
            update(id, new AccountChange(null, change.isActive(), null), actingAccountId, actor);
        }
        AccountRequestEntity filed = new AccountRequestEntity();
        filed.setKind(CHANGE);
        filed.setAccountId(id);
        filed.setUsername(user.getUsername());
        filed.setHeldRole(user.getRole());
        filed.setRequestedRole(roleChanges ? role : null);
        filed.setPasswordHash(password == null ? null : PasswordHasher.hash(password));
        List<String> asked = new ArrayList<>();
        if (roleChanges) {
            asked.add("role " + user.getRole() + " → " + role);
        }
        if (password != null) {
            asked.add("password reset");
        }
        return file(filed, actingAccountId, actor,
                "Account change requested for " + user.getUsername() + ": " + String.join(", ", asked));
    }

    /** The guard rails of {@link #update}, with whoever is acting — the requester, then the approver. */
    void refuseInvalidChange(UserEntity user, String role, boolean isActive, Long actingAccountId) {
        long id = user.getId();
        // Checked on every change and not only on a role change: resetting a governor's password,
        // or deactivating it, is administering it just as much.
        refuseGovernorAdministration(actingAccountId, Role.of(user.getRole()), Role.of(role));
        refuseIfInvalid(AccountRules.refuseSelfLockout(new AccountRules.Change(
                isSelf(actingAccountId, id),
                isAdministrative(user.getRole()) && user.getIsActive(),
                isAdministrative(role),
                isActive,
                (int) countOtherActiveAdmins(id))));
        refuseIfInvalid(AccountRules.refuseOwnRoleChange(isSelf(actingAccountId, id), user.getRole(), role));
    }

    /**
     * Writes a change and who made it; in the caller's transaction.
     *
     * @param role the role to set, or null to keep it
     * @param isActive the activation to set, or null to keep it
     * @param passwordHash the hash of the password to set, or null to keep it
     * @param administrators every account behind the change, for {@link ApproverIndependence}
     * @param provenance appended to the audit sentence: empty, or who asked for and approved it
     */
    Written writeChange(long id, String role, Boolean isActive, String passwordHash, Long actingAccountId,
            List<Long> administrators, String provenance, RequestActor actor) {
        UserEntity user = requireAccount(id);
        String nextRole = role == null ? user.getRole() : role;
        boolean nextActive = isActive == null ? user.getIsActive() : isActive;
        refuseInvalidChange(user, nextRole, nextActive, actingAccountId);

        List<String> changes = new ArrayList<>();
        String previousRole = user.getRole();
        if (!nextRole.equals(user.getRole())) {
            changes.add("role " + user.getRole() + " → " + nextRole);
        }
        if (nextActive != user.getIsActive()) {
            changes.add(nextActive ? "reactivated" : "deactivated");
        }
        if (passwordHash != null) {
            changes.add("password reset");
        }

        if (role != null && user.getScimLoweredFrom() != null) {
            // An administrator who sets the role has looked at the account: the directory's lowering no
            // longer holds its binding back (V93).
            changes.add("role confirmed after the directory lowered it from " + user.getScimLoweredFrom());
            user.setScimLoweredFrom(null);
        }
        Instant at = clock.instant();
        user.setRole(nextRole);
        user.setIsActive(nextActive);
        user.setUpdatedAt(at);
        if (passwordHash != null) {
            user.setPassword(passwordHash);
            user.setMustChangePassword(true);
        }
        // **Three gestures close the sessions, not one.**
        //
        // Deactivating, obviously: otherwise the account stays inside until its session expires
        // and "deactivated" stops meaning anything.
        //
        // But resetting a password too, and that is the one that was missing — even though it is
        // the incident-response gesture. An administrator told of a stolen token resets the
        // password, the screen confirms, and the stolen token goes on authenticating for up to
        // twelve hours, its idle window pushed back on every call. The password changes, the
        // access does not.
        //
        // And changing a role: an open session carries the role re-read on every request, so a
        // demotion does take effect — but closing the session makes that explicit rather than
        // dependent on that detail.
        // The save and the revocation share a transaction, in `AccountAdminService`. They used
        // to be two, which meant a failure between them left the password changed and the
        // session that the change was meant to close still open — the very outcome the
        // paragraph above describes as the defect being fixed.
        boolean revoke = !nextActive || passwordHash != null || !nextRole.equals(previousRole);
        // **A reset takes the account's integration keys too.** A key acts for its account, so
        // one issued by whoever held the stolen credentials outlived the reset that was meant to
        // shut them out: the sessions closed, the pipeline key they minted kept working. Only on a
        // reset — deactivating already stops every key of the account, and a role change moves
        // what they may do with it.
        List<TargetGrants.RevokedKey> revokedKeys = List.of();
        if (passwordHash != null) {
            revokedKeys = accounts.saveRevokingEverything(user);
            if (!revokedKeys.isEmpty()) {
                int count = revokedKeys.size();
                changes.add(count + " API key" + (count == 1 ? "" : "s") + " revoked");
            }
        } else {
            accounts.save(user, revoke);
        }

        List<AccountGesture> made = new ArrayList<>();
        if (passwordHash != null) {
            made.add(AccountGesture.PASSWORD_RESET);
        }
        if (!nextRole.equals(previousRole)) {
            made.add(AccountGesture.ROLE_CHANGED);
        }
        independence.recorded(id, previousRole, administrators, made, at);

        List<AuditLogService.Record> entries = new ArrayList<>();
        if (!changes.isEmpty()) {
            entries.add(entry(actor, id, "Account " + user.getUsername() + ": " + String.join(", ", changes) + provenance));
        }
        // **One entry per key, under the key's id**, as a revocation by hand and one by a target's
        // deletion leave (`TargetDeletionAudit`). A count on the account's entry told nobody which
        // pipeline had just started answering 401, and the SIEM heard no `API_KEY_REVOKED` at all.
        for (TargetGrants.RevokedKey key : revokedKeys) {
            entries.add(new AuditLogService.Record(
                    AuditOperation.API_KEY_DELETED,
                    key.id().toString(),
                    "API key revoked with its account's password reset: " + key.name()
                            + " (account " + user.getUsername() + ")",
                    actor.username(),
                    actor.ipAddress(),
                    actor.userAgent()));
        }
        return new Written(
                new AccountView(UserView.of(user), revoke ? 0 : activeSessionsByUser().getOrDefault(id, 0L)), entries);
    }

    /**
     * Whether a change that makes an approver waits for a second administrator.
     *
     * <p><b>Only under four-eyes</b>, which is the rule that a single person does not decide alone; with it
     * off, nothing changes.
     *
     * <p><b>And only when a second administrator exists</b>, active or not. An installation's first
     * administrator is created by its only one, the governor the bootstrap made; with nobody to approve, the
     * request would wait for ever and the installation could never be staffed. Applied at once then, as before, and the
     * audit entry says so — the same answer {@link TriageApprovers} gives four-eyes itself: a control that
     * cannot be honoured is not one, it is a lock-out.
     */
    private boolean needsSecondAdministrator(Long actingAccountId, Role role) {
        return actingAccountId != null
                && role.approves()
                && settings.isEnabled(Setting.FOUR_EYES_APPROVAL_REQUIRED)
                && countOtherAdmins(actingAccountId) > 0;
    }

    /**
     * Every other administrative account, <b>deactivated ones included</b>: counting the active ones only let an
     * administrator deactivate the others, make an approver "alone", and reactivate them — each step applied at
     * once. A deactivated administrator still waits to be reactivated by somebody, which the requester may do,
     * and the request is then approved by the account reactivated, not by the requester.
     */
    private long countOtherAdmins(long excludedId) {
        List<String> administrative = Role.administrative().stream().map(Enum::name).toList();
        long now = users.countAdministratorsExcluding(administrative, excludedId);
        // And one lowered recently: lowering the others to a role that approves nothing applies at once, and
        // would otherwise leave the lowerer alone as surely as deactivating them did.
        return now > 0 || independence.anotherAdministratorLoweredRecently(excludedId, administrative) ? Math.max(now, 1) : 0;
    }

    /**
     * What the audit sentence adds when four-eyes would have held the change back and nobody else could
     * approve it: the one case in which an administrator makes an approver alone, said where it is read.
     */
    private String appliedAlone(Long actingAccountId, Role role) {
        return actingAccountId != null
                && role.approves()
                && settings.isEnabled(Setting.FOUR_EYES_APPROVAL_REQUIRED)
                && countOtherAdmins(actingAccountId) == 0
                ? " — four-eyes: applied without a second administrator, as there is no other"
                : "";
    }

    /** Files a request, audited under its own id; nothing about the account changes. */
    private Outcome file(AccountRequestEntity filed, Long actingAccountId, RequestActor actor, String description) {
        UserEntity requester = requireAccount(actingAccountId);
        filed.setStatus(PENDING);
        filed.setRequestedById(requester.getId());
        filed.setRequestedBy(requester.getUsername());
        filed.setRequestedAt(clock.instant());
        AccountRequestEntity saved = transaction.execute(status -> {
            // One request waiting per account: under the account's row lock, so that two administrators filing
            // at once are ordered and the second meets the first one's request. A creation has no row to lock;
            // two of the same name are caught by the username's unique key when the second is approved.
            if (filed.getAccountId() != null) {
                users.lockById(filed.getAccountId());
                if (requests.existsByStatusAndAccountId(PENDING, filed.getAccountId())) {
                    throw new ConflictException("A change to " + filed.getUsername()
                            + " is already waiting for approval: have it approved or rejected first.");
                }
            } else if (requests.existsByStatusAndKindAndUsername(PENDING, CREATE, filed.getUsername())) {
                throw new ConflictException("An account named \"" + filed.getUsername()
                        + "\" is already waiting for approval.");
            }
            return requests.save(filed);
        });
        audit.record(actor.entry(AuditOperation.ACCOUNT_REQUEST_FILED, String.valueOf(saved.getId()),
                description + " — four-eyes: waiting for another administrator (account request #" + saved.getId() + ")"));
        return new Outcome.Queued(AccountRequestView.of(saved));
    }

    /**
     * Lifts another account's obligation to change its password, for an account that signs in through
     * the identity provider.
     *
     * <p><b>Why it exists.</b> The directory created its accounts, on 0.10.0 and {@code v0.11.0-rc.1},
     * with a random password and the flag; every federated session of such an account is held on the
     * change-password screen, which asks for a current password nobody has. The release notes of 0.11.0
     * could only offer an {@code update} statement.
     *
     * <p><b>Why only for an account bound to a provider subject.</b> The flag is the control that makes a
     * password somebody else chose — the bootstrap one in the deployment's configuration, the one an
     * administrator typed at a creation or a reset — stop being a credential. Lifting it on an account that
     * signs in with that password would keep it valid for good, known to whoever chose it, and
     * indistinguishable from its owner's use. That account lifts the flag itself, by changing the password.
     * One with no password at all has nothing to keep valid.
     *
     * <p><b>The lift discards the local password.</b> Being bound to a provider subject does not stop the
     * password sign-in from accepting the stored hash: binding by single sign-on or by the directory keeps
     * the password the account had. Lifting the flag alone therefore left the password somebody else chose a
     * working credential, for good. The same save replaces it with one nobody knows, as the directory does
     * for the accounts it creates, so the account signs in through the provider only — and an administrator
     * who wants it to sign in with a password again resets one, which sets the flag again.
     *
     * <p><b>Its sessions close; its integration keys stay.</b> A session held on the change-password screen
     * may have been opened with that password, by whoever chose it, and the lift would turn it into a full
     * one: the account's owner signs in again through the provider. No key can have been issued under the
     * flag — the server holds every route but the change-password ones while it is set, and a reset, the
     * other way to set it, revokes the account's keys — so the keys the account holds are its owner's, issued
     * before, and revoking them would stop their pipelines for nothing.
     *
     * <p><b>Never on one's own account</b>, as nobody changes their own role: a control is lifted by somebody
     * other than the person it binds. An administrator owing a change cannot reach the route anyway — the
     * server holds them on the change-password routes — and this refusal does not lean on that holding.
     *
     * <p><b>Idempotent.</b> An account that owes nothing is answered as it is, with no write and no entry:
     * the request's outcome already holds, and a retry after a lost answer is not a second action.
     *
     * @param actingAccountId the account clearing it. Read, not trusted: it must hold an administrative role
     *     today, whatever the route's marker admitted
     * @throws AccessDeniedException when the caller is not an administrative account
     */
    public AccountView clearPasswordChangeRequirement(long id, Long actingAccountId, RequestActor actor) {
        boolean administers = actingAccountId != null && users.findById(actingAccountId)
                .flatMap(account -> Role.of(account.getRole()))
                .map(Role::isAdministrative)
                .orElse(false);
        if (!administers) {
            throw new AccessDeniedException("Only an administrator can lift another account's password-change requirement.");
        }
        UserEntity user = requireAccount(id);
        if (isSelf(actingAccountId, id)) {
            throw new InvalidInputException("You cannot lift your own password-change requirement: change your password.");
        }
        refuseGovernorAdministration(actingAccountId, Role.of(user.getRole()), Optional.empty());

        if (!user.getMustChangePassword()) {
            return new AccountView(UserView.of(user), activeSessionsByUser().getOrDefault(id, 0L));
        }
        if (signsInWithItsPassword(user)) {
            throw new InvalidInputException("This account signs in with its password, which somebody else chose: "
                    + "it lifts the requirement itself by changing it. Only an account that signs in through the "
                    + "identity provider can have it lifted.");
        }

        user.setMustChangePassword(false);
        if (user.getPassword() != null) {
            // 122 random bits, never shown: the hash stays a well-formed one, so the sign-in's constant-time
            // comparison runs as for any account, and nothing anybody typed matches it.
            user.setPassword(PasswordHasher.hash(UUID.randomUUID().toString()));
        }
        user.setUpdatedAt(clock.instant());
        accounts.save(user, true);
        record(actor, id, "Account " + user.getUsername()
                + ": password-change requirement lifted, local password discarded");
        return new AccountView(UserView.of(user), activeSessionsByUser().getOrDefault(id, 0L));
    }

    /**
     * Clears another account's second factor, and closes its sessions.
     *
     * <p><b>The way back for an account locked out of its own factor.</b> Enrolling asks for the
     * password, but a lost phone, or a factor enrolled by whoever held the password and a session, used
     * to be recoverable only in the database. Disabling asks for a current code, which is exactly what
     * the owner no longer has.
     *
     * <p>Never one's own — an administrator who could clear their own factor would make it a password
     * again — and under the governor's rules, as a password reset is: the governor's factor is the
     * governor's. The sessions close because a factor enrolled by somebody else came with a session of
     * theirs. The account's API keys stay: resetting the password, as for any suspected compromise, is
     * what takes them.
     *
     * <p><b>Idempotent.</b> An account without a factor is answered as it is, with no write and no entry.
     *
     * @param actingAccountId the account clearing it. Read, not trusted: it must hold an administrative role
     *     today, whatever the route's marker admitted
     * @throws AccessDeniedException when the caller is not an administrative account
     */
    public AccountView resetSecondFactor(long id, Long actingAccountId, RequestActor actor) {
        boolean administers = actingAccountId != null && users.findById(actingAccountId)
                .flatMap(account -> Role.of(account.getRole()))
                .map(Role::isAdministrative)
                .orElse(false);
        if (!administers) {
            throw new AccessDeniedException("Only an administrator can reset another account's second factor.");
        }
        UserEntity user = requireAccount(id);
        if (isSelf(actingAccountId, id)) {
            throw new InvalidInputException("You cannot reset your own second factor: disable it with a current code.");
        }
        refuseGovernorAdministration(actingAccountId, Role.of(user.getRole()), Optional.empty());

        if (!user.getMfaEnabled()) {
            return new AccountView(UserView.of(user), activeSessionsByUser().getOrDefault(id, 0L));
        }
        user.setMfaEnabled(false);
        user.setTotpSecret(null);
        user.setMfaBackupCodes(null);
        user.setTotpLastStep(null);
        user.setUpdatedAt(clock.instant());
        accounts.save(user, true);
        record(actor, id, "Account " + user.getUsername() + ": second factor reset by an administrator, sessions closed");
        return new AccountView(UserView.of(user), 0);
    }

    /** Holds a password and no provider subject: the password is how it signs in. */
    private static boolean signsInWithItsPassword(UserEntity user) {
        return user.getPassword() != null && user.getKeycloakId() == null;
    }

    /**
     * The targets this account may see, each named. Empty means it sees nothing, in restricted mode.
     *
     * <p>A project grant is listed as the project, not as its repositories: the grant is what an
     * administrator made and can revoke, and what it resolves to changes as repositories are filed.
     *
     * <p>By kind, then id — the primary key's order, made explicit so that the pages are the list cut on every
     * engine — all of them or one page, named for the page's rows only.
     *
     * @param limit rows per page, or null for every target ({@link ListWindow#requested})
     * @throws InvalidInputException a window the rule refuses — after the account's 404
     */
    public List<GrantableTargets.TargetGrant> targets(long id, Integer limit, Integer offset) {
        requireAccount(id);
        Optional<ListWindow> window = ListWindow.requested(limit, offset);
        List<TargetAssignment> every = assignments.findByUserId(id).stream()
                .map(row -> new TargetAssignment(row.getId().targetKind(), row.getId().targetId()))
                .sorted(TargetAssignment.ORDER)
                .toList();
        return targets.named(window.map(page -> page.of(every)).orElse(every));
    }

    /**
     * Replaces the set wholesale.
     *
     * <p>Wholesale rather than add-and-remove, because the operation that matters is
     * <em>removing</em> one: a screen that sends what it wants and a server that only adds is a
     * revocation that silently does nothing.
     *
     * <p><b>Read as the team path reads it.</b> A null entry, or one with no id, is skipped; the kind
     * is validated against those that exist and lowercased, and a new grant's target must exist and
     * be one the granter sees — a grant already held is kept as it is ({@link GrantTargets}). The body used
     * to reach the table as sent: {@code [null]} or a missing id was a 500 from the insert, and an
     * unknown kind was stored — an assignment the screen showed and that granted nothing.
     *
     * @param requested as sent, possibly null or holding nulls
     * @param granter what the administrator granting may see: a new grant outside it, or naming a
     *     target that does not exist, is refused as absent ({@link GrantTargets})
     * @return the assignments as stored, which is what the screen must show — not what it sent
     */
    public List<GrantableTargets.TargetGrant> replaceTargets(
            long id, List<TargetAssignment> requested, Visibility granter, RequestActor actor) {
        UserEntity user = requireAccount(id);
        java.util.Set<TargetAssignment> held = assignments.findByUserId(id).stream()
                .map(row -> new TargetAssignment(row.getId().targetKind(), row.getId().targetId()))
                .collect(java.util.stream.Collectors.toSet());

        // A set, because the pair is the table's primary key: the same target sent twice is one
        // assignment, not a constraint violation.
        java.util.LinkedHashSet<TargetAssignment> unique = new java.util.LinkedHashSet<>();
        for (TargetAssignment assignment : requested == null ? List.<TargetAssignment>of() : requested) {
            if (assignment == null || assignment.id() == null) {
                continue;
            }
            String kind = grantTargets.validate(assignment.kind(), assignment.id(), granter,
                    (normalized, targetId) -> held.contains(new TargetAssignment(normalized, targetId)));
            unique.add(new TargetAssignment(kind, assignment.id()));
        }
        List<TargetAssignment> wanted = List.copyOf(unique);

        accounts.replaceTargets(id, wanted.stream()
                .map(assignment -> new UserTargetEntity(id, assignment.kind(), assignment.id()))
                .toList());

        // Audited like a role change, because it is the same kind of decision: it changes what
        // somebody can read, by a gesture just as quiet.
        record(actor, id,
                "Visible targets of " + user.getUsername() + ": "
                        + (wanted.isEmpty() ? "none" : wanted.size() + " assigned"));
        return targets.named(wanted);
    }

    /** @param actingAccountId as for {@link #update}: refuses deleting one's own account */
    public void delete(long id, Long actingAccountId, RequestActor actor) {
        UserEntity user = requireAccount(id);
        refuseGovernorAdministration(actingAccountId, Role.of(user.getRole()), Optional.empty());

        refuseIfInvalid(AccountRules.refuseDeletion(
                isSelf(actingAccountId, id), isAdministrative(user.getRole()) && user.getIsActive(), (int) countOtherActiveAdmins(id)));

        accounts.delete(id);
        record(actor, id, "Account deleted: " + user.getUsername());
    }

    UserEntity requireAccount(long id) {
        return users.findById(id).orElseThrow(() -> new NotFoundException("Account not found."));
    }

    /** See {@link AccountRules#refuseGovernorAdministration}; the acting role is read, not trusted. */
    private void refuseGovernorAdministration(Long actingAccountId, Optional<Role> current, Optional<Role> next) {
        Optional<Role> acting = actingAccountId == null
                ? Optional.empty()
                : users.findById(actingAccountId).flatMap(account -> Role.of(account.getRole()));
        refuseIfInvalid(AccountRules.refuseGovernorAdministration(acting, current, next));
    }

    private static boolean isSelf(Long actingAccountId, long id) {
        return actingAccountId != null && actingAccountId.equals(id);
    }

    private long countOtherActiveAdmins(long excludedId) {
        return users.countActiveAdministratorsExcluding(
                Role.administrative().stream().map(Enum::name).toList(), excludedId);
    }

    private Map<Long, Long> activeSessionsByUser() {
        Map<Long, Long> counts = new HashMap<>();
        for (Object[] row : sessions.countActiveByUser(clock.instant())) {
            counts.put(((Number) row[0]).longValue(), ((Number) row[1]).longValue());
        }
        return counts;
    }

    private void record(RequestActor actor, long id, String description) {
        audit.record(entry(actor, id, description));
    }

    private static AuditLogService.Record entry(RequestActor actor, long id, String description) {
        return new AuditLogService.Record(
                AuditOperation.USER_UPDATED,
                String.valueOf(id),
                description,
                actor.username(),
                actor.ipAddress(),
                actor.userAgent());
    }

    private static boolean approves(String role) {
        return Role.of(role).map(Role::approves).orElse(false);
    }

    private static boolean isAdministrative(String role) {
        return Role.of(role).map(Role::isAdministrative).orElse(false);
    }

    private static void refuseIfInvalid(Optional<String> refusal) {
        refusal.ifPresent(message -> {
            throw new InvalidInputException(message);
        });
    }

    private static String trim(String value) {
        return value == null ? "" : value.trim();
    }
}
