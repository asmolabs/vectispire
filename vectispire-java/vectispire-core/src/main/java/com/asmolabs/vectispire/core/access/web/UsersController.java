package com.asmolabs.vectispire.core.access.web;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.paging.ListWindow;
import com.asmolabs.vectispire.core.access.AccountAdministrationService.AccountView;
import com.asmolabs.vectispire.core.access.AccountAdministrationService;
import com.asmolabs.vectispire.core.access.GrantableTargets;
import com.asmolabs.vectispire.core.access.UserView;
import com.asmolabs.vectispire.core.access.VisibilityService;
import com.asmolabs.vectispire.core.access.web.security.RequestActors;
import com.asmolabs.vectispire.core.access.web.security.RequiresAdministrator;
import com.asmolabs.vectispire.core.access.web.security.VectispirePrincipal;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/** Managing accounts. Administrators only, enforced at the entry point. */
@RestController
@RequestMapping("/api/v1/users")
@RequiresAdministrator
public class UsersController {

    private final AccountAdministrationService accounts;
    private final VisibilityService visibility;

    public UsersController(AccountAdministrationService accounts, VisibilityService visibility) {
        this.visibility = visibility;
        this.accounts = accounts;
    }

    /**
     * What an account shows.
     *
     * <p>{@code password} is not on it, and never must be: a password hash that leaves the
     * server is a hash to crack offline.
     *
     * @param federated bound to an identity provider's subject: it signs in through the provider, and
     *     only such an account may have its password-change requirement lifted by somebody else
     */
    public record UserAdminSummary(
            Long id,
            String username,
            String email,
            String displayName,
            String role,
            boolean isActive,
            boolean mustChangePassword,
            boolean federated,
            Instant createdAt,
            long activeSessions) {}

    /**
     * @param total every account the list holds — {@code users}' length unless a page was asked for, as the
     *     backlog's and the audit log's pages count theirs
     */
    public record UserListing(List<UserAdminSummary> users, Long currentUserId, long total) {}

    /**
     * A grant as the screen sends it.
     *
     * @param kind {@code repository}, {@code container} or {@code project}. What comes back is a
     *     {@code TargetGrant}, which adds the target's name: a project is in no list the screen
     *     already holds, so it could not label one
     */
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
    public UserListing list(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @Parameter(description = ListWindow.LIMIT_ON_REQUEST,
                    schema = @Schema(minimum = "1", maximum = "" + ListWindow.MAX_LIMIT))
            @RequestParam(required = false) Integer limit,
            @Parameter(description = ListWindow.OFFSET_ON_REQUEST, schema = @Schema(minimum = "0"))
            @RequestParam(required = false) Integer offset) {
        AccountAdministrationService.Accounts listed = accounts.list(limit, offset);
        List<UserAdminSummary> summaries = listed.accounts().stream().map(UsersController::summaryOf).toList();

        // The screen needs to know which account is its own, so it does not offer actions the
        // server will refuse anyway.
        return new UserListing(summaries, principal.user().map(UserView::id).orElse(null), listed.total());
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

    /**
     * Lifts the account's obligation to change its password — for an account the identity provider
     * signs in, never one's own; see {@link AccountAdministrationService#clearPasswordChangeRequirement}.
     *
     * <p>{@code DELETE} on the requirement, like the plugins' waiver and the agents' sealing key: what
     * is removed is a thing the account owes. It answers the account as it now stands, whether or not it
     * owed anything — the outcome holds either way.
     */
    @DeleteMapping("/{id}/password-change-requirement")
    public UserAdminSummary clearPasswordChangeRequirement(
            @PathVariable long id,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        return summaryOf(accounts.clearPasswordChangeRequirement(
                id, actingAccountId(principal), RequestActors.of(principal, request)));
    }

    /** The targets this account may see. Empty means it sees nothing, in restricted mode. */
    @GetMapping("/{id}/targets")
    public List<GrantableTargets.TargetGrant> targets(@PathVariable long id) {
        return accounts.targets(id);
    }

    /** Replaces the set wholesale, so that removing a target is something the screen can do. */
    @PutMapping("/{id}/targets")
    public List<GrantableTargets.TargetGrant> setTargets(
            @PathVariable long id,
            @RequestBody List<UserTargetAssignment> body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        // Null entries are carried through rather than filtered here, as on the team route: what
        // an entry must hold is the service's rule, and `Stream.toList` keeps nulls.
        List<AccountAdministrationService.TargetAssignment> requested = (body == null ? List.<UserTargetAssignment>of() : body)
                .stream()
                .map(assignment -> assignment == null
                        ? null
                        : new AccountAdministrationService.TargetAssignment(assignment.kind(), assignment.id()))
                .toList();
        // What was stored, not what was sent: the two differ by every entry the service skipped or
        // normalized, and a screen showing the request would show assignments that do not exist.
        return accounts.replaceTargets(id, requested, granter(principal), RequestActors.of(principal, request));
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void remove(
            @PathVariable long id,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        accounts.delete(id, actingAccountId(principal), RequestActors.of(principal, request));
    }

    /** What the administrator granting may see: a grant is refused as absent outside it. */
    private Visibility granter(VectispirePrincipal principal) {
        return visibility.of(principal.user().orElse(null), principal.credentialRestriction());
    }

    private static Long actingAccountId(VectispirePrincipal principal) {
        return principal.user().map(UserView::id).orElse(null);
    }

    private static UserAdminSummary summaryOf(AccountView view) {
        UserView user = view.user();
        return new UserAdminSummary(
                user.id(),
                user.username(),
                user.email(),
                user.displayName(),
                user.role(),
                user.isActive(),
                user.mustChangePassword(),
                user.keycloakId() != null,
                user.createdAt(),
                view.activeSessions());
    }
}
