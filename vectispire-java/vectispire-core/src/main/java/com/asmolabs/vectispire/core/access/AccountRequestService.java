package com.asmolabs.vectispire.core.access;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.errors.ConflictException;
import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.common.domain.errors.NotFoundException;
import com.asmolabs.vectispire.common.domain.paging.ListWindow;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.access.AccountAdministrationService.AccountView;
import com.asmolabs.vectispire.core.access.AccountAdministrationService.NewAccount;
import com.asmolabs.vectispire.core.access.AccountAdministrationService.Written;
import com.asmolabs.vectispire.core.access.persistence.AccountRequestEntity;
import com.asmolabs.vectispire.core.access.persistence.AccountRequestRepository;
import com.asmolabs.vectispire.core.access.persistence.UserEntity;
import com.asmolabs.vectispire.core.access.persistence.UserRepository;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.audit.RequestActor;
import java.time.Clock;
import java.util.List;
import java.util.Optional;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * The account changes waiting for a second administrator under four-eyes: listed, approved, rejected
 * (#126, option 2). {@link AccountAdministrationService} files them; this applies or drops them.
 *
 * <p><b>Like a triage waiting for approval, and refused on the same grounds.</b> Somebody other than the
 * requester approves it — two administrators, not one acting twice — and, as for a triage, somebody the
 * requester did not administer recently ({@link ApproverIndependence}): an approval by an account the
 * requester has just made would be the requester's own. Nobody approves a change to their own account,
 * which would let a reset's typed password be confirmed by the account it opens.
 *
 * <p><b>Applied as the approver.</b> The change is checked again with the approver as the acting account —
 * who may grant the governor role, who may change whose — since it is the approver who now makes it, and the
 * account may have changed since it was filed: a role that moved in between makes the request stale rather
 * than overwriting whoever moved it. The requester and the approver are both recorded as having administered
 * the account.
 *
 * <p><b>Decided under the request's row lock</b>, in one transaction with the change, so two administrators
 * deciding at once are ordered: the second reads the first one's decision. The audit entries follow the
 * commit, as every account gesture's do.
 */
@Service
public class AccountRequestService {

    private static final String APPROVED = "approved";
    private static final String REJECTED = "rejected";

    private final AccountRequestRepository requests;
    private final UserRepository users;
    private final AccountAdministrationService administration;
    private final ApproverIndependence independence;
    private final AuditLogService audit;
    private final Clock clock;
    private final TransactionTemplate transaction;

    public AccountRequestService(
            AccountRequestRepository requests,
            UserRepository users,
            AccountAdministrationService administration,
            ApproverIndependence independence,
            AuditLogService audit,
            Clock clock,
            PlatformTransactionManager transactionManager) {
        this.requests = requests;
        this.users = users;
        this.administration = administration;
        this.independence = independence;
        this.audit = audit;
        this.clock = clock;
        this.transaction = new TransactionTemplate(transactionManager);
    }

    /**
     * The requests waiting on one page, and how many wait on every page.
     *
     * @param total the requests waiting, whether or not the page shows them all
     */
    public record Pending(List<AccountRequestView> requests, long total) {}

    /**
     * The requests waiting, oldest first — all of them, or one page.
     *
     * @param limit rows per page, or null for every request ({@link ListWindow#requested})
     * @throws InvalidInputException a window the rule refuses
     */
    public Pending pending(Integer limit, Integer offset) {
        Optional<ListWindow> window = ListWindow.requested(limit, offset);
        List<AccountRequestView> every = requests.findByStatusOrderByRequestedAtAscIdAsc(AccountAdministrationService.PENDING)
                .stream().map(AccountRequestView::of).toList();
        return new Pending(window.map(page -> page.of(every)).orElse(every), every.size());
    }

    /**
     * Applies a request as its approver, and answers the account as it now stands.
     *
     * @param approverId the account approving. Read, not trusted: it must hold an administrative role today
     * @throws AccessDeniedException when the caller is not an administrative account
     * @throws NotFoundException no such request
     * @throws ConflictException the request was already decided, its account changed since it was filed, its
     *     requester is no longer an active administrator, the approver and the requester administered one another
     *     ({@link ApproverNotIndependentException}), or a raise's account had its password set by either of them
     *     ({@link PasswordKnownException})
     * @throws OwnAccountRequestException the approver filed it
     */
    public AccountView approve(long id, Long approverId, RequestActor actor) {
        UserEntity approver = requireAdministrator(approverId, "approve");
        Approved approved = transaction.execute(status -> {
            AccountRequestEntity request = requirePending(id);
            if (request.getRequestedById().equals(approver.getId())) {
                throw new OwnAccountRequestException();
            }
            if (approver.getId().equals(request.getAccountId())) {
                throw new InvalidInputException("You cannot approve a change to your own account.");
            }
            // The requester's standing is read now, not when it filed: a request whose author has since been
            // deactivated or demoted — on suspicion, as often as not — has nobody left standing behind it.
            boolean requesterStands = users.findById(request.getRequestedById())
                    .filter(UserEntity::getIsActive)
                    .filter(account -> Role.of(account.getRole()).map(Role::isAdministrative).orElse(false))
                    .isPresent();
            if (!requesterStands) {
                throw new ConflictException(request.getRequestedBy() + " is no longer an active administrator: "
                        + "reject this request, and file the change again if it is still wanted.");
            }
            independence.requireMutual(request.getRequestedById(), request.getRequestedBy(), approver.getId());

            String provenance = ", requested by " + request.getRequestedBy() + " and approved by "
                    + approver.getUsername() + " (account request #" + request.getId() + ")";
            List<Long> administrators = List.of(request.getRequestedById(), approver.getId());
            Written written;
            if (AccountAdministrationService.CREATE.equals(request.getKind())) {
                written = administration.writeCreation(
                        new NewAccount(request.getUsername(), null, request.getRequestedRole(), request.getEmail(),
                                request.getDisplayName()),
                        request.getPasswordHash(), approver.getId(), administrators, provenance, actor);
            } else {
                UserEntity account = administration.requireAccount(request.getAccountId());
                if (!account.getRole().equals(request.getHeldRole())) {
                    throw new ConflictException("The role of " + account.getUsername() + " changed since this request "
                            + "was filed: reject it, and file the change again if it is still wanted.");
                }
                if (raisesToAnApprover(request)) {
                    // Neither administrator behind the raise may know the account's password from a gesture of
                    // theirs: lower, reset, raise would otherwise hand one of them an approver.
                    independence.requirePasswordUnknown(account.getId(), account.getUsername(),
                            request.getRequestedById(), request.getRequestedBy());
                    independence.requirePasswordUnknown(account.getId(), account.getUsername(),
                            approver.getId(), approver.getUsername());
                }
                written = administration.writeChange(request.getAccountId(), request.getRequestedRole(), null,
                        request.getPasswordHash(), approver.getId(), administrators, provenance, actor);
            }
            request.setStatus(APPROVED);
            request.setDecidedBy(approver.getUsername());
            request.setDecidedAt(clock.instant());
            // The hash is applied: the request keeps no copy of a password the account now holds.
            request.setPasswordHash(null);
            requests.save(request);
            return new Approved(written, request.getRequestedBy());
        });
        audit.record(actor.entry(AuditOperation.ACCOUNT_REQUEST_APPROVED, String.valueOf(id),
                "Account request #" + id + " by " + approved.requester() + " approved"));
        approved.written().entries().forEach(audit::record);
        return approved.written().account();
    }

    /**
     * Drops a request, applying nothing. Any administrator may — its requester included, which withdraws it.
     *
     * @param deciderId the account rejecting. Read, not trusted: it must hold an administrative role today
     * @throws AccessDeniedException when the caller is not an administrative account
     * @throws NotFoundException no such request
     * @throws ConflictException the request was already decided
     */
    public void reject(long id, Long deciderId, RequestActor actor) {
        UserEntity decider = requireAdministrator(deciderId, "reject");
        String requester = transaction.execute(status -> {
            AccountRequestEntity request = requirePending(id);
            request.setStatus(REJECTED);
            request.setDecidedBy(decider.getUsername());
            request.setDecidedAt(clock.instant());
            request.setPasswordHash(null);
            requests.save(request);
            return request.getRequestedBy();
        });
        audit.record(actor.entry(AuditOperation.ACCOUNT_REQUEST_REJECTED, String.valueOf(id),
                "Account request #" + id + " by " + requester
                        + (requester.equals(decider.getUsername()) ? " withdrawn" : " rejected")));
    }

    private static boolean raisesToAnApprover(AccountRequestEntity request) {
        return request.getRequestedRole() != null
                && !request.getRequestedRole().equals(request.getHeldRole())
                && Role.of(request.getRequestedRole()).map(Role::approves).orElse(false);
    }

    /** A change written, and who asked for it, for the entries after the commit. */
    private record Approved(Written written, String requester) {}

    private AccountRequestEntity requirePending(long id) {
        AccountRequestEntity request = requests.lockForDecision(id)
                .orElseThrow(() -> new NotFoundException("Account request not found."));
        if (!AccountAdministrationService.PENDING.equals(request.getStatus())) {
            throw new ConflictException("This request was already " + request.getStatus() + " by "
                    + request.getDecidedBy() + ".");
        }
        return request;
    }

    private UserEntity requireAdministrator(Long accountId, String gesture) {
        return Optional.ofNullable(accountId)
                .flatMap(users::findById)
                .filter(UserEntity::getIsActive)
                .filter(account -> Role.of(account.getRole()).map(Role::isAdministrative).orElse(false))
                .orElseThrow(() -> new AccessDeniedException("Only an administrator can " + gesture + " an account request."));
    }

    /**
     * An account request approved by the administrator who filed it: 409, with the type {@code
     * urn:vectispire:problem:own-account-request} and the code {@code own-account-request}.
     */
    public static final class OwnAccountRequestException extends ConflictException {

        /** The token the problem's {@code type} ends with, published in the route's description. */
        public static final String CAUSE = "own-account-request";

        OwnAccountRequestException() {
            super("You filed this request: four-eyes needs another administrator to approve it.", CAUSE);
        }
    }
}
