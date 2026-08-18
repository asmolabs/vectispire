package com.asmolabs.zanshin.core.api;

import com.asmolabs.zanshin.common.domain.audit.AuditOperation;
import com.asmolabs.zanshin.common.domain.crypto.PasswordHasher;
import com.asmolabs.zanshin.common.domain.users.AccountRules;
import com.asmolabs.zanshin.common.domain.users.Role;
import com.asmolabs.zanshin.core.api.security.ZanshinPrincipal;
import com.asmolabs.zanshin.core.persistence.UserEntity;
import com.asmolabs.zanshin.core.repositories.UserSessions;
import com.asmolabs.zanshin.core.repositories.Users;
import com.asmolabs.zanshin.core.services.AuditLogService;
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
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/** Managing accounts. Administrators only, enforced at the entry point. */
@RestController
@RequestMapping("/api/v1/users")
@PreAuthorize("hasAnyRole('SUPERUSER', 'ADMIN')")
public class UsersController {

    private final Users users;
    private final UserSessions sessions;
    private final AuditLogService audit;
    private final Clock clock;

    public UsersController(Users users, UserSessions sessions, AuditLogService audit, Clock clock) {
        this.users = users;
        this.sessions = sessions;
        this.audit = audit;
        this.clock = clock;
    }

    /**
     * What an account shows.
     *
     * <p>{@code password} is not on it, and never must be: a password hash that leaves the
     * server is a hash to crack offline.
     */
    public record Summary(
            Long id,
            String username,
            String email,
            String displayName,
            String role,
            boolean isActive,
            boolean mustChangePassword,
            Instant createdAt,
            long activeSessions) {}

    public record Listing(List<Summary> users, Long currentUserId) {}

    public record CreateRequest(String username, String password, String role, String email, String displayName) {}

    /** Every field optional: absent means "leave it as it is", which is what PATCH means. */
    public record UpdateRequest(String role, Boolean isActive, String password) {}

    @GetMapping
    public Listing list(@AuthenticationPrincipal ZanshinPrincipal principal) {
        Map<Long, Long> active = activeSessionsByUser();
        List<Summary> summaries = new ArrayList<>();
        users.findAllByOrderByUsernameAsc()
                .forEach(user -> summaries.add(summaryOf(user, active.getOrDefault(user.getId(), 0L))));

        // The screen needs to know which account is its own, so it does not offer actions the
        // server will refuse anyway.
        return new Listing(summaries, principal.user().map(UserEntity::getId).orElse(null));
    }

    @PostMapping
    public Summary create(
            @RequestBody CreateRequest body,
            @AuthenticationPrincipal ZanshinPrincipal principal,
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
    public Summary update(
            @PathVariable long id,
            @RequestBody UpdateRequest body,
            @AuthenticationPrincipal ZanshinPrincipal principal,
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
        users.save(user);

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
        boolean revoke = !isActive || password != null || !role.equals(previousRole);
        if (revoke) {
            sessions.deleteByUserId(id);
        }

        if (!changes.isEmpty()) {
            record(principal, request, id, "Account " + user.getUsername() + ": " + String.join(", ", changes));
        }
        return summaryOf(user, revoke ? 0 : activeSessionsByUser().getOrDefault(id, 0L));
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void remove(
            @PathVariable long id,
            @AuthenticationPrincipal ZanshinPrincipal principal,
            HttpServletRequest request) {

        UserEntity user = users.findById(id).orElseThrow(() -> new NoSuchElementException("Account not found."));

        boolean isSelf = principal.user().map(current -> current.getId().equals(id)).orElse(false);
        refuseIfInvalid(AccountRules.refuseDeletion(
                isSelf, isAdministrative(user.getRole()) && user.getIsActive(), (int) countOtherActiveAdmins(id)));

        sessions.deleteByUserId(id);
        users.deleteById(id);
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

    private void record(ZanshinPrincipal principal, HttpServletRequest request, long id, String description) {
        audit.record(new AuditLogService.Record(
                AuditOperation.USER_UPDATED,
                String.valueOf(id),
                description,
                principal.user().map(UserEntity::getUsername).orElse(null),
                request.getRemoteAddr(),
                request.getHeader("User-Agent")));
    }

    private static Summary summaryOf(UserEntity user, long activeSessions) {
        return new Summary(
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
