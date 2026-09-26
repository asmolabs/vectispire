package com.asmolabs.vectispire.core.services.access;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.crypto.PasswordHasher;
import com.asmolabs.vectispire.common.domain.text.BoundedText;
import com.asmolabs.vectispire.common.domain.users.AccountRules;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.audit.RequestActor;
import com.asmolabs.vectispire.core.persistence.UserEntity;
import com.asmolabs.vectispire.core.persistence.UserTargetEntity;
import com.asmolabs.vectispire.core.repositories.UserSessions;
import com.asmolabs.vectispire.core.repositories.UserTargets;
import com.asmolabs.vectispire.core.repositories.Users;
import com.asmolabs.vectispire.core.services.shared.TargetNaming;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Optional;
import org.springframework.stereotype.Service;

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
 * <p>Every refusal is an {@link IllegalArgumentException} carrying text meant for the screen, and
 * every missing account a {@link NoSuchElementException} — the 400 and the 404 the handler maps.
 */
@Service
public class AccountAdministrationService {

    /** The width of {@code email} and {@code display_name}. */
    private static final int BOUNDED_COLUMN = 255;

    private final Users users;
    private final UserSessions sessions;
    private final UserTargets assignments;
    private final AccountAdminService accounts;
    private final AuditLogService audit;
    private final Clock clock;
    private final GrantTargets grantTargets;
    private final TargetNaming naming;

    public AccountAdministrationService(
            Users users,
            UserSessions sessions,
            UserTargets assignments,
            AccountAdminService accounts,
            AuditLogService audit,
            Clock clock,
            GrantTargets grantTargets,
            TargetNaming naming) {
        this.users = users;
        this.sessions = sessions;
        this.assignments = assignments;
        this.accounts = accounts;
        this.audit = audit;
        this.clock = clock;
        this.grantTargets = grantTargets;
        this.naming = naming;
    }

    /** An account and how many live sessions it holds. */
    public record AccountView(UserView user, long activeSessions) {}

    /** @param kind {@code repository}, {@code container} or {@code project} */
    public record TargetAssignment(String kind, Long id) implements TargetNaming.Grant {}

    public record NewAccount(String username, String password, String role, String email, String displayName) {}

    /** Every field optional: absent means "leave it as it is". */
    public record AccountChange(String role, Boolean isActive, String password) {}

    public List<AccountView> list() {
        Map<Long, Long> active = activeSessionsByUser();
        List<AccountView> views = new ArrayList<>();
        users.findAllByOrderByUsernameAsc()
                .forEach(user -> views.add(new AccountView(UserView.of(user), active.getOrDefault(user.getId(), 0L))));
        return views;
    }

    /**
     * @param actingAccountId the account creating it, or null for a caller that is not one — who
     *     may grant the platform governor role depends on it
     */
    public AccountView create(NewAccount request, Long actingAccountId, RequestActor actor) {
        String username = trim(request.username());
        String password = request.password() == null ? "" : request.password();
        String role = trim(request.role()).isEmpty() ? Role.USER.name() : trim(request.role()).toUpperCase(Locale.ROOT);

        refuseIfInvalid(AccountRules.validateUsername(username));
        refuseIfInvalid(AccountRules.validatePassword(password));
        if (Role.of(role).isEmpty()) {
            throw new IllegalArgumentException("Unknown role: " + role + ".");
        }
        refuseGovernorAdministration(actingAccountId, Optional.empty(), Role.of(role));
        if (users.findByUsername(username).isPresent()) {
            throw new IllegalArgumentException("The username \"" + username + "\" is already taken.");
        }

        Instant createdAt = clock.instant();
        UserEntity user = new UserEntity();
        user.setUsername(username);
        // Bounded like every column a form writes: past 255 the database refused the row at the
        // write, and the administrator got a 500 for a pasted signature block.
        user.setEmail(BoundedText.optional(request.email(), BOUNDED_COLUMN, "The e-mail address"));
        user.setDisplayName(BoundedText.optional(request.displayName(), BOUNDED_COLUMN, "The display name"));
        user.setPassword(PasswordHasher.hash(password));
        user.setRole(role);
        user.setIsActive(true);
        // The password set here is known to the administrator who typed it: it is a pass, not
        // the account's secret.
        user.setMustChangePassword(true);
        user.setCreatedAt(createdAt);
        user.setUpdatedAt(createdAt);

        UserEntity saved = users.save(user);
        record(actor, saved.getId(), "Account created: " + username + " (" + role + ")");
        return new AccountView(UserView.of(saved), 0);
    }

    /**
     * Role, activation and password reset.
     *
     * <p>The three carry the same guard rails, so there is one entry point rather than three to
     * keep in step.
     *
     * @param actingAccountId the account making the change, or null for a caller that is not one —
     *     used to recognise a change to one's own account. Apart from the audit identity, because
     *     only this service needs it
     */
    public AccountView update(long id, AccountChange change, Long actingAccountId, RequestActor actor) {
        UserEntity user = requireAccount(id);

        String role = change.role() == null ? user.getRole() : trim(change.role()).toUpperCase(Locale.ROOT);
        boolean isActive = change.isActive() == null ? user.getIsActive() : change.isActive();
        String password = change.password();

        if (Role.of(role).isEmpty()) {
            throw new IllegalArgumentException("Unknown role: " + role + ".");
        }
        if (password != null) {
            refuseIfInvalid(AccountRules.validatePassword(password));
        }

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

        List<String> changes = new ArrayList<>();
        String previousRole = user.getRole();
        if (!role.equals(user.getRole())) {
            changes.add("role " + user.getRole() + " → " + role);
        }
        if (isActive != user.getIsActive()) {
            changes.add(isActive ? "reactivated" : "deactivated");
        }
        if (password != null) {
            changes.add("password reset");
        }

        user.setRole(role);
        user.setIsActive(isActive);
        user.setUpdatedAt(clock.instant());
        if (password != null) {
            user.setPassword(PasswordHasher.hash(password));
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
        boolean revoke = !isActive || password != null || !role.equals(previousRole);
        accounts.save(user, revoke);

        if (!changes.isEmpty()) {
            record(actor, id, "Account " + user.getUsername() + ": " + String.join(", ", changes));
        }
        return new AccountView(UserView.of(user), revoke ? 0 : activeSessionsByUser().getOrDefault(id, 0L));
    }

    /**
     * The targets this account may see, each named. Empty means it sees nothing, in restricted mode.
     *
     * <p>A project grant is listed as the project, not as its repositories: the grant is what an
     * administrator made and can revoke, and what it resolves to changes as repositories are filed.
     */
    public List<TargetNaming.TargetGrant> targets(long id) {
        requireAccount(id);
        return naming.named(assignments.findByUserId(id).stream()
                .map(row -> new TargetAssignment(row.getId().targetKind(), row.getId().targetId()))
                .toList());
    }

    /**
     * Replaces the set wholesale.
     *
     * <p>Wholesale rather than add-and-remove, because the operation that matters is
     * <em>removing</em> one: a screen that sends what it wants and a server that only adds is a
     * revocation that silently does nothing.
     *
     * <p><b>Read as the team path reads it.</b> A null entry, or one with no id, is skipped; the kind
     * is validated against those that exist and lowercased, and a project must exist. The body used
     * to reach the table as sent: {@code [null]} or a missing id was a 500 from the insert, and an
     * unknown kind was stored — an assignment the screen showed and that granted nothing.
     *
     * @param requested as sent, possibly null or holding nulls
     * @return the assignments as stored, which is what the screen must show — not what it sent
     */
    public List<TargetNaming.TargetGrant> replaceTargets(
            long id, List<TargetAssignment> requested, RequestActor actor) {
        UserEntity user = requireAccount(id);

        // A set, because the pair is the table's primary key: the same target sent twice is one
        // assignment, not a constraint violation.
        java.util.LinkedHashSet<TargetAssignment> unique = new java.util.LinkedHashSet<>();
        for (TargetAssignment assignment : requested == null ? List.<TargetAssignment>of() : requested) {
            if (assignment == null || assignment.id() == null) {
                continue;
            }
            unique.add(new TargetAssignment(grantTargets.validate(assignment.kind(), assignment.id()), assignment.id()));
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
        return naming.named(wanted);
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

    private UserEntity requireAccount(long id) {
        return users.findById(id).orElseThrow(() -> new NoSuchElementException("Account not found."));
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
        audit.record(new AuditLogService.Record(
                AuditOperation.USER_UPDATED,
                String.valueOf(id),
                description,
                actor.username(),
                actor.ipAddress(),
                actor.userAgent()));
    }

    private static boolean isAdministrative(String role) {
        return Role.of(role).map(Role::isAdministrative).orElse(false);
    }

    private static void refuseIfInvalid(Optional<String> refusal) {
        refusal.ifPresent(message -> {
            throw new IllegalArgumentException(message);
        });
    }

    private static String trim(String value) {
        return value == null ? "" : value.trim();
    }
}
