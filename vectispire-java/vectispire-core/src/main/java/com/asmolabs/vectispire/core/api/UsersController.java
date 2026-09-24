package com.asmolabs.vectispire.core.api;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.asmolabs.vectispire.core.api.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.persistence.UserEntity;
import com.asmolabs.vectispire.core.services.AccountAdministrationService;
import com.asmolabs.vectispire.core.services.AccountAdministrationService.AccountView;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.util.List;
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

    private final AccountAdministrationService accounts;

    public UsersController(AccountAdministrationService accounts) {
        this.accounts = accounts;
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
        List<UserAdminSummary> summaries = accounts.list().stream().map(UsersController::summaryOf).toList();

        // The screen needs to know which account is its own, so it does not offer actions the
        // server will refuse anyway.
        return new UserListing(summaries, principal.user().map(UserEntity::getId).orElse(null));
    }

    @PostMapping
    public UserAdminSummary create(
            @RequestBody UserCreateRequest body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        return summaryOf(accounts.create(
                new AccountAdministrationService.NewAccount(
                        body.username(), body.password(), body.role(), body.email(), body.displayName()),
                actingAccountId(principal),
                RequestActors.of(principal, request)));
    }

    /**
     * Role, activation and password reset — and which of them close the account's sessions,
     * which is decided in {@link AccountAdministrationService#update}.
     */
    @PatchMapping("/{id}")
    public UserAdminSummary update(
            @PathVariable long id,
            @RequestBody UserUpdateRequest body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        return summaryOf(accounts.update(
                id,
                new AccountAdministrationService.AccountChange(body.role(), body.isActive(), body.password()),
                actingAccountId(principal),
                RequestActors.of(principal, request)));
    }

    /** The targets this account may see. Empty means it sees nothing, in restricted mode. */
    @GetMapping("/{id}/targets")
    public List<UserTargetAssignment> targets(@PathVariable long id) {
        return accounts.targets(id).stream()
                .map(assignment -> new UserTargetAssignment(assignment.kind(), assignment.id()))
                .toList();
    }

    /** Replaces the set wholesale, so that removing a target is something the screen can do. */
    @PutMapping("/{id}/targets")
    public List<UserTargetAssignment> setTargets(
            @PathVariable long id,
            @RequestBody List<UserTargetAssignment> body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        List<UserTargetAssignment> wanted = body == null ? List.of() : body;
        accounts.replaceTargets(
                id,
                wanted.stream()
                        .map(assignment -> new AccountAdministrationService.TargetAssignment(
                                assignment.kind(), assignment.id()))
                        .toList(),
                RequestActors.of(principal, request));
        return wanted;
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void remove(
            @PathVariable long id,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        accounts.delete(id, actingAccountId(principal), RequestActors.of(principal, request));
    }

    private static Long actingAccountId(VectispirePrincipal principal) {
        return principal.user().map(UserEntity::getId).orElse(null);
    }

    private static UserAdminSummary summaryOf(AccountView view) {
        UserEntity user = view.user();
        return new UserAdminSummary(
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                user.getDisplayName(),
                user.getRole(),
                user.getIsActive(),
                user.getMustChangePassword(),
                user.getCreatedAt(),
                view.activeSessions());
    }
}
