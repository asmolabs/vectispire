package com.asmolabs.vectispire.core.access.web;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.paging.ListWindow;
import com.asmolabs.vectispire.core.access.AccountAdministrationService;
import com.asmolabs.vectispire.core.access.AccountAdministrationService.AccountView;
import com.asmolabs.vectispire.core.access.AccountAdministrationService.Outcome;
import com.asmolabs.vectispire.core.access.AccountRequestView;
import com.asmolabs.vectispire.core.access.DirectoryManagedException;
import com.asmolabs.vectispire.core.access.GrantableTargets;
import com.asmolabs.vectispire.core.access.UserView;
import com.asmolabs.vectispire.core.access.VisibilityService;
import com.asmolabs.vectispire.core.access.web.security.RequestActors;
import com.asmolabs.vectispire.core.access.web.security.RequiresAdministrator;
import com.asmolabs.vectispire.core.access.web.security.VectispirePrincipal;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
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
     * @param scimManaged written by the SCIM directory, which replaces its e-mail address on every
     *     synchronisation: a change to it is refused here, and the screen says so before it is tried
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
            long activeSessions,
            // Whether a local second factor is enrolled: the screen offers to reset it only then.
            boolean mfaEnabled,
            boolean scimManaged) {}

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

    /**
     * Every field optional: absent means "leave it as it is", which is what PATCH means.
     *
     * @param email the address to set — blank clears it, the one the account holds changes nothing
     */
    public record UserUpdateRequest(
            String role,
            @JsonProperty("is_active") Boolean isActive,
            String password,
            @Schema(description = "The address to set: absent or null leaves it, blank clears it, the one the "
                    + "account holds changes nothing. At most 255 characters, shaped like name@example.org, held "
                    + "by no other account. Refused with 409 managed-by-directory on an account the SCIM "
                    + "directory writes.")
            String email) {}

    @GetMapping
    public UserListing list(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @Parameter(description = ListWindow.LIMIT_ON_REQUEST,
                    schema = @Schema(type = "integer", format = "int32", minimum = "1", maximum = "" + ListWindow.MAX_LIMIT))
            @RequestParam(required = false) Integer limit,
            @Parameter(description = ListWindow.OFFSET_ON_REQUEST, schema = @Schema(type = "integer", format = "int32", minimum = "0"))
            @RequestParam(required = false) Integer offset) {
        AccountAdministrationService.Accounts listed = accounts.list(limit, offset);
        List<UserAdminSummary> summaries = listed.accounts().stream().map(UsersController::summaryOf).toList();

        // The screen needs to know which account is its own, so it does not offer actions the
        // server will refuse anyway.
        return new UserListing(summaries, principal.user().map(UserView::id).orElse(null), listed.total());
    }

    /**
     * Creates an account — or, under four-eyes, files the creation of one whose role approves (an
     * administrator, a CISO, a security champion, the governor) for a second administrator: 202 and the
     * request, which {@code /api/v1/account-requests} lists and decides.
     */
    @PostMapping
    @ApiResponse(responseCode = "200", description = "The account, created",
            content = @Content(schema = @Schema(implementation = UserAdminSummary.class)))
    @ApiResponse(responseCode = "202", description = FILED,
            content = @Content(schema = @Schema(implementation = AccountRequestView.class)))
    public ResponseEntity<Object> create(
            @RequestBody UserCreateRequest body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        return answer(accounts.create(
                new AccountAdministrationService.NewAccount(
                        body.username(), body.password(), body.role(), body.email(), body.displayName()),
                actingAccountId(principal),
                RequestActors.of(principal, request)));
    }

    /**
     * Role, activation, e-mail address and password reset — and which of them close the account's
     * sessions, which is decided in {@link AccountAdministrationService#update}. Under four-eyes, a role
     * raised to one that approves, or a password reset of an account holding one, is filed for a second
     * administrator: 202 and the request.
     *
     * <p>409 with the type {@code urn:vectispire:problem:managed-by-directory} (code {@code managed-by-directory})
     * for a change of the e-mail address of an account the SCIM directory writes, which is changed in the
     * directory; plain 409 when a change to the account is already waiting for approval.
     */
    @PatchMapping("/{id}")
    @Operation(description = "Changes an account's role, activation, e-mail address or password; every field left "
            + "out is left as it is. 409 with the type urn:vectispire:problem:" + DirectoryManagedException.CAUSE
            + " (code " + DirectoryManagedException.CAUSE + ") for a change of the e-mail address of an account the "
            + "SCIM directory writes (scimManaged), which is changed in the directory; plain 409 when a change to the "
            + "account is already waiting for approval.")
    @ApiResponse(responseCode = "200", description = "The account, changed",
            content = @Content(schema = @Schema(implementation = UserAdminSummary.class)))
    @ApiResponse(responseCode = "202", description = FILED,
            content = @Content(schema = @Schema(implementation = AccountRequestView.class)))
    public ResponseEntity<Object> update(
            @PathVariable long id,
            @RequestBody UserUpdateRequest body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        return answer(accounts.update(
                id,
                new AccountAdministrationService.AccountChange(body.role(), body.isActive(), body.password(), body.email()),
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

    /**
     * Clears another account's second factor and closes its sessions — never one's own; see
     * {@link AccountAdministrationService#resetSecondFactor}. {@code DELETE}, like the password-change
     * requirement: what is removed is a thing the account holds, and the answer is the account as it
     * now stands.
     */
    @DeleteMapping("/{id}/second-factor")
    public UserAdminSummary resetSecondFactor(
            @PathVariable long id,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        return summaryOf(accounts.resetSecondFactor(id, actingAccountId(principal), RequestActors.of(principal, request)));
    }

    /** The targets this account may see. Empty means it sees nothing, in restricted mode. */
    @GetMapping("/{id}/targets")
    public List<GrantableTargets.TargetGrant> targets(
            @PathVariable long id,
            @Parameter(description = ListWindow.LIMIT_ON_REQUEST,
                    schema = @Schema(type = "integer", format = "int32", minimum = "1", maximum = "" + ListWindow.MAX_LIMIT))
            @RequestParam(required = false) Integer limit,
            @Parameter(description = ListWindow.OFFSET_ON_REQUEST, schema = @Schema(type = "integer", format = "int32", minimum = "0"))
            @RequestParam(required = false) Integer offset) {
        return accounts.targets(id, limit, offset);
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

    /** What a 202 of the create and update routes says. */
    private static final String FILED = "Four-eyes: the change makes an approver and waits for another "
            + "administrator's approval. Nothing has changed yet; the body is the request, decided under "
            + "/api/v1/account-requests. An activation, a deactivation or an e-mail address sent with it has been applied.";

    /** An applied change answers the account, a filed one the request. */
    private static ResponseEntity<Object> answer(Outcome outcome) {
        return switch (outcome) {
            case Outcome.Applied applied -> ResponseEntity.ok(summaryOf(applied.account()));
            case Outcome.Queued queued -> ResponseEntity.accepted().body(queued.request());
        };
    }

    /** What the administrator granting may see: a grant is refused as absent outside it. */
    private Visibility granter(VectispirePrincipal principal) {
        return visibility.of(principal.user().orElse(null), principal.credentialRestriction());
    }

    private static Long actingAccountId(VectispirePrincipal principal) {
        return principal.user().map(UserView::id).orElse(null);
    }

    static UserAdminSummary summaryOf(AccountView view) {
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
                view.activeSessions(),
                user.mfaEnabled(),
                user.scimManaged());
    }
}
