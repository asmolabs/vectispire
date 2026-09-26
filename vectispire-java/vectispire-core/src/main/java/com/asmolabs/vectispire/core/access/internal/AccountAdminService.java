package com.asmolabs.vectispire.core.access.internal;

import com.asmolabs.vectispire.core.access.AccountAdministrationService;
import com.asmolabs.vectispire.core.access.persistence.UserEntity;
import com.asmolabs.vectispire.core.access.persistence.SessionRepository;
import com.asmolabs.vectispire.core.access.persistence.UserTargetEntity;
import com.asmolabs.vectispire.core.access.persistence.UserTargetRepository;
import com.asmolabs.vectispire.core.access.persistence.UserRepository;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import java.util.List;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * The account gestures that are more than one write.
 *
 * <p><b>This class exists for its transaction boundary and nothing else.</b> Each of the three
 * methods below was two or three repository calls in {@code UsersController}, and every
 * repository call carries its own {@code @Transactional} — so each one committed on its own.
 * Nothing joined them, and {@code open-in-view} is off, so there was no ambient transaction to
 * join either.
 *
 * <p><b>What that cost, on the path where it matters most.</b> Resetting a password and closing
 * the account's sessions is the incident-response gesture: an administrator is told a token was
 * stolen, resets the password, and expects the stolen token to stop working. With two
 * transactions, a failure between them — a lock timeout, a connection dropped, the process
 * killed — leaves the password changed, the screen confirming, and the stolen session alive for
 * the rest of its twelve hours. The behaviour {@link AccountAdministrationService#update} documents
 * at length as the one that had been missing came back in exactly the circumstances where it is least likely to
 * be noticed: when something has already gone wrong.
 *
 * <p><b>The audit entry deliberately stays outside.</b> {@link AuditLogService#record} runs
 * {@code REQUIRES_NEW} so that an audited action which rolls back is still recorded as attempted
 * — see the note on that method. Pulling it in here would undo that, and the caller writes it
 * after these methods return for the same reason.
 */
@Service
public class AccountAdminService {

    private final UserRepository users;
    private final SessionRepository sessions;
    private final UserTargetRepository assignments;

    public AccountAdminService(UserRepository users, SessionRepository sessions, UserTargetRepository assignments) {
        this.users = users;
        this.sessions = sessions;
        this.assignments = assignments;
    }

    /**
     * Saves an account and, when the change demands it, closes its sessions — together or not at
     * all.
     *
     * <p>The caller decides <em>whether</em> to revoke, because that rule is about roles and
     * activation and belongs with them. What is decided here is that the two writes share a fate.
     */
    @Transactional
    public UserEntity save(UserEntity user, boolean revokeSessions) {
        UserEntity saved = users.save(user);
        if (revokeSessions) {
            sessions.deleteByUserId(saved.getId());
        }
        return saved;
    }

    /**
     * Replaces an account's visible targets wholesale.
     *
     * <p>Delete-then-insert is the repository's documented shape, and it is the half-applied
     * outcome that this boundary rules out: a failure between the two used to leave the account
     * seeing an arbitrary subset of what the administrator submitted — and an account that can
     * see <em>some</em> of the estate is the one state nobody would think to check for.
     */
    @Transactional
    public void replaceTargets(long userId, List<UserTargetEntity> wanted) {
        assignments.deleteByUserId(userId);
        wanted.forEach(assignments::save);
    }

    /**
     * Deletes an account with its sessions.
     *
     * <p>Sessions first, then the row: that order was already the defensive one, since a failure
     * after the first leaves an account nobody can be signed in to rather than a deleted account
     * somebody is still using. It is now moot — either both happen or neither does.
     *
     * <p>The target assignments are not deleted here: {@code t_user_target} carries {@code on
     * delete cascade} on {@code user_id} since {@code V19}, and a second authority for the same
     * removal is how the two drift.
     */
    @Transactional
    public void delete(long userId) {
        sessions.deleteByUserId(userId);
        users.deleteById(userId);
    }
}
