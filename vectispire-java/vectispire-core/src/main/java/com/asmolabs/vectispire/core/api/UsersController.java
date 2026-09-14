package com.asmolabs.vectispire.core.api;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.crypto.PasswordHasher;
import com.asmolabs.vectispire.common.domain.users.AccountRules;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.api.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.persistence.UserEntity;
import com.asmolabs.vectispire.core.persistence.UserTargetEntity;
import com.asmolabs.vectispire.core.repositories.UserSessions;
import com.asmolabs.vectispire.core.repositories.UserTargets;
import com.asmolabs.vectispire.core.repositories.Users;
import com.asmolabs.vectispire.core.services.AccountAdminService;
import com.asmolabs.vectispire.core.services.AuditLogService;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Optional;
import org.springframework.http.HttpStatus;
import com.asmolabs.vectispire.core.api.security.RequiresAdministrator;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/** Managing accounts. Administrators only, enforced at the entry point. */
@RestController
@RequestMapping("/api/v1/users")
@RequiresAdministrator
public class UsersController {

    private final Users users;
    private final UserSessions sessions;
    private final UserTargets assignments;
    private final AccountAdminService accounts;
    private final AuditLogService audit;
    private final Clock clock;

    public UsersController(
            Users users,
            UserSessions sessions,
            UserTargets assignments,
            AccountAdminService accounts,
            AuditLogService audit,
            Clock clock) {
        this.users = users;
        this.sessions = sessions;
        this.assignments = assignments;
        this.accounts = accounts;
        this.audit = audit;
        this.clock = clock;
    }

    /**
     * What an account shows.
     *
     * <p>{@code password} is not on it, and never must be: a password hash that leaves the
     * server is a hash to crack offline.
     */
    public record UserAdminSummary(
            Long id,
            String username,
            String email,
            String displayName,
            String role,
            boolean isActive,
            boolean mustChangePassword,
            Instant createdAt,
            long activeSessions) {}

    public record UserListing(List<UserAdminSummary> users, Long currentUserId) {}

    /** @param kind {@code repository} or {@code container} */
    public record UserTargetAssignment(String kind, Long id) {}

    /** The names the Angular client sends. See {@code ClientContractTest} for why they differ. */
    public record UserCreateRequest(
            String username,
            String password,
            String role,
            String email,
            @JsonProperty("display_name") String displayName) {}

    /** Every field optional: absent means "leave it as it is", which is what PATCH means. */
    public record UserUpdateRequest(String role, @JsonProperty("is_active") Boolean isActive, String password) {}

    @GetMapping
    public UserListing list(@AuthenticationPrincipal VectispirePrincipal principal) {
        Map<Long, Long> active = activeSessionsByUser();
        List<UserAdminSummary> summaries = new ArrayList<>();
        users.findAllByOrderByUsernameAsc()
                .forEach(user -> summaries.add(summaryOf(user, active.getOrDefault(user.getId(), 0L))));

        // The screen needs to know which account is its own, so it does not offer actions the
        // server will refuse anyway.
        return new UserListing(summaries, principal.user().map(UserEntity::getId).orElse(null));
    }

    @PostMapping
    public UserAdminSummary create(
            @RequestBody UserCreateRequest body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {

        String username = trim(body.username());
        String password = body.password() == null ? "" : body.password();
        String role = trim(body.role()).isEmpty() ? Role.USER.name() : trim(body.role()).toUpperCase(Locale.ROOT);

        refuseIfInvalid(AccountRules.validateUsername(username));
        refuseIfInvalid(AccountRules.validatePassword(password));
        if (Role.of(role).isEmpty()) {
            throw new IllegalArgumentException("Unknown role: " + role + ".");
        }
        if (users.findByUsername(username).isPresent()) {
            throw new IllegalArgumentException("The username \"" + username + "\" is already taken.");
        }

        Instant createdAt = clock.instant();
        UserEntity user = new UserEntity();
        user.setUsername(username);
        user.setEmail(optional(body.email()));
        user.setDisplayName(optional(body.displayName()));
        user.setPassword(PasswordHasher.hash(password));
        user.setRole(role);
        user.setIsActive(true);
        // The password set here is known to the administrator who typed it: it is a pass, not
        // the account's secret.
        user.setMustChangePassword(true);
        user.setCreatedAt(createdAt);
        user.setUpdatedAt(createdAt);

        UserEntity saved = users.save(user);
        record(principal, request, saved.getId(), "Account created: " + username + " (" + role + ")");
        return summaryOf(saved, 0);
    }

    /**
     * Role, activation and password reset.
     *
     * <p>The three carry the same guard rails, so there is one entry point rather than three to
     * keep in step.
     */
    @PatchMapping("/{id}")
    public UserAdminSummary update(
            @PathVariable long id,
            @RequestBody UserUpdateRequest body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {

        UserEntity user = users.findById(id).orElseThrow(() -> new NoSuchElementException("Account not found."));

        String role = body.role() == null ? user.getRole() : trim(body.role()).toUpperCase(Locale.ROOT);
        boolean isActive = body.isActive() == null ? user.getIsActive() : body.isActive();
        String password = body.password();

        if (Role.of(role).isEmpty()) {
            throw new IllegalArgumentException("Unknown role: " + role + ".");
        }
        if (password != null) {
            refuseIfInvalid(AccountRules.validatePassword(password));
        }

        boolean isSelf = principal.user().map(current -> current.getId().equals(id)).orElse(false);
        refuseIfInvalid(AccountRules.refuseSelfLockout(new AccountRules.Change(
                isSelf,
                isAdministrative(user.getRole()) && user.getIsActive(),
                isAdministrative(role),
                isActive,
                (int) countOtherActiveAdmins(id))));

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
            record(principal, request, id, "Account " + user.getUsername() + ": " + String.join(", ", changes));
        }
        return summaryOf(user, revoke ? 0 : activeSessionsByUser().getOrDefault(id, 0L));
    }

    /** The targets this account may see. Empty means it sees nothing, in restricted mode. */
    @GetMapping("/{id}/targets")
    public List<UserTargetAssignment> targets(@PathVariable long id) {
        users.findById(id).orElseThrow(() -> new NoSuchElementException("Account not found."));
        return assignments.findByUserId(id).stream()
                .map(row -> new UserTargetAssignment(row.getId().targetKind(), row.getId().targetId()))
                .toList();
    }

    /**
     * Replaces the set wholesale.
     *
     * <p>Wholesale rather than add-and-remove, because the operation that matters is
     * <em>removing</em> one: a screen that sends what it wants and a server that only adds is a
     * revocation that silently does nothing.
     */
    @PutMapping("/{id}/targets")
    public List<UserTargetAssignment> setTargets(
            @PathVariable long id,
            @RequestBody List<UserTargetAssignment> body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {

        UserEntity user = users.findById(id).orElseThrow(() -> new NoSuchElementException("Account not found."));
        List<UserTargetAssignment> wanted = body == null ? List.of() : body;

        accounts.replaceTargets(id, wanted.stream()
                .map(assignment -> new UserTargetEntity(id, assignment.kind(), assignment.id()))
                .toList());

        // Audited like a role change, because it is the same kind of decision: it changes what
        // somebody can read, by a gesture just as quiet.
        record(principal, request, id,
                "Visible targets of " + user.getUsername() + ": "
                        + (wanted.isEmpty() ? "none" : wanted.size() + " assigned"));
        return wanted;
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void remove(
            @PathVariable long id,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {

        UserEntity user = users.findById(id).orElseThrow(() -> new NoSuchElementException("Account not found."));

        boolean isSelf = principal.user().map(current -> current.getId().equals(id)).orElse(false);
        refuseIfInvalid(AccountRules.refuseDeletion(
                isSelf, isAdministrative(user.getRole()) && user.getIsActive(), (int) countOtherActiveAdmins(id)));

        accounts.delete(id);
        record(principal, request, id, "Account deleted: " + user.getUsername());
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

    private void record(VectispirePrincipal principal, HttpServletRequest request, long id, String description) {
        audit.record(new AuditLogService.Record(
                AuditOperation.USER_UPDATED,
                String.valueOf(id),
                description,
                principal.user().map(UserEntity::getUsername).orElse(null),
                request.getRemoteAddr(),
                request.getHeader("User-Agent")));
    }

    private static UserAdminSummary summaryOf(UserEntity user, long activeSessions) {
        return new UserAdminSummary(
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                user.getDisplayName(),
                user.getRole(),
                user.getIsActive(),
                user.getMustChangePassword(),
                user.getCreatedAt(),
                activeSessions);
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

    private static String optional(String value) {
        String trimmed = trim(value);
        return trimmed.isEmpty() ? null : trimmed;
    }
}
