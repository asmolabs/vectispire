package com.asmolabs.vectispire.core.access;

import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.users.AccountGesture;
import com.asmolabs.vectispire.core.access.persistence.AccountAdministrationEntity;
import com.asmolabs.vectispire.core.access.persistence.AccountAdministrationRepository;
import com.asmolabs.vectispire.core.access.persistence.UserEntity;
import com.asmolabs.vectispire.core.access.persistence.UserRepository;
import com.asmolabs.vectispire.core.settings.SettingsService;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Whether the second pair of eyes is somebody else's: under four-eyes, an approval is refused when the
 * requester created the approver's account, reset its password or changed its role within the window the
 * platform governor sets — thirty days unless it says otherwise (#126, option 1).
 *
 * <p><b>Why two identities are not two people.</b> Four-eyes compared the requester's name with the
 * approver's, and an administrator who wanted a decision through could make the second name: create an
 * account with an approving role, or reset the password of one that holds it, sign in with the password
 * just typed and approve. The audit log showed every step and nothing stopped any of them. This asks the
 * question the name comparison could not: did the requester hold the approver's account in their hands
 * recently?
 *
 * <p><b>What it reads.</b> {@code t_account_administration}, written in the transaction of each gesture
 * (V100), and not the audit log, whose entries say which gesture in a sentence. A gesture made before the
 * upgrade is not there: the window starts filling on the day 1.0 is installed.
 *
 * <p><b>With four-eyes off, nothing.</b> A single person may then settle anything, and refusing an approver
 * would refuse what anybody could have done directly. A window of zero switches the check off as well, which
 * the governor alone may set, and which is forwarded to the SOC like every rule it changes.
 */
@Service
public class ApproverIndependence {

    private final AccountAdministrationRepository gestures;
    private final UserRepository users;
    private final SettingsService settings;
    private final Clock clock;

    public ApproverIndependence(
            AccountAdministrationRepository gestures, UserRepository users, SettingsService settings, Clock clock) {
        this.gestures = gestures;
        this.users = users;
        this.settings = settings;
        this.clock = clock;
    }

    /**
     * Refuses an approval whose requester administered the approver's account within the window.
     *
     * <p>By name, as a triage's history records its requester. A name that is no account any more — the
     * requester deleted, an exemption filed before accounts had names here — has administered nothing this
     * table can show, and is let through: the name comparison before this one still refuses the same name.
     *
     * @throws ApproverNotIndependentException under four-eyes, when the requester administered the approver
     */
    @Transactional(readOnly = true)
    public void require(String requesterUsername, String approverUsername) {
        if (requesterUsername == null || approverUsername == null || !applies()) {
            return;
        }
        Optional<UserEntity> requester = users.findByUsername(requesterUsername.trim());
        Optional<UserEntity> approver = users.findByUsername(approverUsername.trim());
        if (requester.isPresent() && approver.isPresent()) {
            refuse(requester.get().getId(), requester.get().getUsername(), approver.get().getId());
        }
    }

    /**
     * Refuses an approval whose requester administered the approver's account within the window — by
     * account, as an account request records its requester.
     *
     * @throws ApproverNotIndependentException under four-eyes, when the requester administered the approver
     */
    @Transactional(readOnly = true)
    public void require(long requesterId, String requesterUsername, long approverId) {
        if (applies()) {
            refuse(requesterId, requesterUsername, approverId);
        }
    }

    /**
     * Refuses an account-request approval when either administrator administered the other within the window.
     *
     * <p><b>Both ways, for account requests only.</b> An administrator whose creation another one filed and
     * the first approved may be the filer's own second name: from then on it files and the filer approves, and
     * the one-way question — did the requester administer the approver? — never sees the creation. A triage
     * keeps the one-way question: an approver may settle directly, so an approver who created a developer's
     * account gains nothing by approving that developer's request, and refusing it would refuse every
     * administrator who staffed the team they review.
     *
     * @throws ApproverNotIndependentException under four-eyes, when either administered the other
     */
    @Transactional(readOnly = true)
    public void requireMutual(long requesterId, String requesterName, long approverId) {
        if (!applies()) {
            return;
        }
        refuse(requesterId, requesterName, approverId);
        newest(requesterId, approverId).ifPresent(gesture -> {
            throw ApproverNotIndependentException.ofRequester(requesterName, gesture, windowDays());
        });
    }

    /**
     * Refuses a raise to a role that approves when this administrator created the account or reset its password
     * within the window: it may know the password, and the raise would hand it an approver.
     *
     * @throws PasswordKnownException under four-eyes, when the administrator set the account's password
     */
    @Transactional(readOnly = true)
    public void requirePasswordUnknown(long accountId, String accountName, long administratorId, String administratorName) {
        if (!applies() || accountId == administratorId) {
            return;
        }
        Instant since = clock.instant().minus(Duration.ofDays(windowDays()));
        gestures.findByAccountIdAndAdministratorIdAndOccurredAtGreaterThanEqualOrderByOccurredAtDesc(
                        accountId, administratorId, since).stream()
                .map(row -> AccountGesture.fromWireName(row.getGesture()))
                .flatMap(Optional::stream)
                .filter(gesture -> gesture != AccountGesture.ROLE_CHANGED)
                .findFirst()
                .ifPresent(gesture -> {
                    throw new PasswordKnownException(administratorName, accountName, gesture, windowDays());
                });
    }

    /**
     * Records that an administrator made one of the three gestures on an account. Called in the transaction
     * that applies the gesture, so the account never changes without its record.
     *
     * @param administrators every account behind the gesture — the one that applied it, and the requester
     *     of an approved request: each of them knew the password, or chose the role
     */
    @Transactional
    public void recorded(long accountId, String heldRole, Collection<Long> administrators,
            Collection<AccountGesture> made, Instant at) {
        for (Long administrator : administrators) {
            // Not one's own account: an administrator changing their own password is no second identity.
            if (administrator == null || administrator == accountId) {
                continue;
            }
            for (AccountGesture gesture : made) {
                gestures.save(new AccountAdministrationEntity(accountId, administrator, gesture.wireName(), heldRole, at));
            }
        }
    }

    /**
     * Whether an account other than this one left an administrative role within the window — at least thirty
     * days, whatever the window: counting the administrators there are now let one lower the others to a role
     * that approves nothing, each lowering applied at once, and then act "alone".
     */
    @Transactional(readOnly = true)
    public boolean anotherAdministratorLoweredRecently(long excluding, Collection<String> administrativeRoles) {
        int days = Math.max(windowDays(), 30);
        return gestures.anyChangedFromSince(AccountGesture.ROLE_CHANGED.wireName(), administrativeRoles,
                clock.instant().minus(Duration.ofDays(days)), excluding);
    }

    private boolean applies() {
        return settings.isEnabled(Setting.FOUR_EYES_APPROVAL_REQUIRED) && windowDays() > 0;
    }

    private int windowDays() {
        // The setting's own validation bounds it; a row written around it is read at its bound rather than
        // failing the approval with a date before the first instant there is.
        return Math.clamp(settings.asInt(Setting.FOUR_EYES_INDEPENDENCE_DAYS), 0, Setting.MAX_INDEPENDENCE_DAYS);
    }

    private void refuse(long requesterId, String requesterName, long approverId) {
        if (requesterId == approverId) {
            // The same account is the same person: the callers refuse it in their own words first.
            return;
        }
        newest(approverId, requesterId).ifPresent(gesture -> {
            throw ApproverNotIndependentException.ofApprover(requesterName, gesture, windowDays());
        });
    }

    /** The newest gesture this administrator made on this account within the window. */
    private Optional<AccountGesture> newest(long accountId, long administratorId) {
        if (accountId == administratorId) {
            return Optional.empty();
        }
        Instant since = clock.instant().minus(Duration.ofDays(windowDays()));
        List<AccountAdministrationEntity> made = gestures
                .findByAccountIdAndAdministratorIdAndOccurredAtGreaterThanEqualOrderByOccurredAtDesc(
                        accountId, administratorId, since);
        return made.stream()
                .map(row -> AccountGesture.fromWireName(row.getGesture()))
                .flatMap(Optional::stream)
                .findFirst();
    }
}
