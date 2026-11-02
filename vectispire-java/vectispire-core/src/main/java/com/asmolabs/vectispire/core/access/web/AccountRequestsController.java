package com.asmolabs.vectispire.core.access.web;

import com.asmolabs.vectispire.common.domain.paging.ListWindow;
import com.asmolabs.vectispire.core.access.AccountRequestService;
import com.asmolabs.vectispire.core.access.AccountRequestView;
import com.asmolabs.vectispire.core.access.UserView;
import com.asmolabs.vectispire.core.access.web.UsersController.UserAdminSummary;
import com.asmolabs.vectispire.core.access.web.security.RequestActors;
import com.asmolabs.vectispire.core.access.web.security.RequiresAdministrator;
import com.asmolabs.vectispire.core.access.web.security.VectispirePrincipal;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * The account changes waiting for a second administrator under four-eyes (#126, option 2): an account
 * created with a role that approves, a role raised to one, the password of an account holding one reset.
 * Administrators only, enforced at the entry point; who may approve which is {@link AccountRequestService}'s.
 */
@RestController
@RequestMapping("/api/v1/account-requests")
@RequiresAdministrator
public class AccountRequestsController {

    private final AccountRequestService requests;

    public AccountRequestsController(AccountRequestService requests) {
        this.requests = requests;
    }

    /**
     * @param total every request waiting — {@code requests}' length unless a page was asked for
     */
    public record AccountRequestListing(List<AccountRequestView> requests, long total) {}

    /** The requests waiting, oldest first. A decided request is in the audit log, not here. */
    @GetMapping
    @Operation(operationId = "listAccountRequests")
    public AccountRequestListing list(
            @Parameter(description = ListWindow.LIMIT_ON_REQUEST,
                    schema = @Schema(type = "integer", format = "int32", minimum = "1", maximum = "" + ListWindow.MAX_LIMIT))
            @RequestParam(required = false) Integer limit,
            @Parameter(description = ListWindow.OFFSET_ON_REQUEST, schema = @Schema(type = "integer", format = "int32", minimum = "0"))
            @RequestParam(required = false) Integer offset) {
        AccountRequestService.Pending pending = requests.pending(limit, offset);
        return new AccountRequestListing(pending.requests(), pending.total());
    }

    /**
     * Applies the request, as the approver, and answers the account as it now stands.
     *
     * <p>409 when the request was already decided or its account changed since; with the type {@code
     * urn:vectispire:problem:own-account-request} (code {@code own-account-request}) when the approver filed
     * it; with {@code urn:vectispire:problem:approver-not-independent} (code {@code approver-not-independent})
     * when, within the approver independence window, either of them created the other's account, reset its
     * password or changed its role; with {@code urn:vectispire:problem:password-known-to-administrator} when a
     * raise's account had its password set by the requester or the approver within the window; plain 409 when the
     * requester is no longer an active administrator. 400 for a change to the approver's own account, or one the rules refuse
     * with the approver acting.
     */
    @PostMapping("/{id}/approve")
    @Operation(operationId = "approveAccountRequest")
    public UserAdminSummary approve(
            @PathVariable long id,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        return UsersController.summaryOf(
                requests.approve(id, actingAccountId(principal), RequestActors.of(principal, request)));
    }

    /** Drops the request, applying nothing; its requester may, which withdraws it. 409 when already decided. */
    @PostMapping("/{id}/reject")
    @Operation(operationId = "rejectAccountRequest")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void reject(
            @PathVariable long id,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        requests.reject(id, actingAccountId(principal), RequestActors.of(principal, request));
    }

    private static Long actingAccountId(VectispirePrincipal principal) {
        return principal.user().map(UserView::id).orElse(null);
    }
}
