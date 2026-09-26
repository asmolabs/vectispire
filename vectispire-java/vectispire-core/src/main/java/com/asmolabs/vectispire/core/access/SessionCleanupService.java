package com.asmolabs.vectispire.core.access;

import com.asmolabs.vectispire.common.domain.auth.LoginThrottle;
import com.asmolabs.vectispire.core.access.persistence.LoginAttempts;
import com.asmolabs.vectispire.core.access.persistence.MfaChallenges;
import com.asmolabs.vectispire.core.access.persistence.UserSessions;
import java.time.Clock;
import java.time.Duration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Purging the authentication tables.
 *
 * <p>It purged the gate's verdict register and the compliance captures too, through a port those
 * modules implemented; since step 5 each contributes its own periodic task, and this pass keeps the
 * three tables that are {@code access}'s (decision 0029).
 *
 * <p><b>This is not a security control, and saying so matters.</b> An expired session is
 * already refused on read, and an attempt outside the window is already not counted. This pass
 * makes nothing safer: it only stops two tables accumulating rows nobody will ever read.
 *
 * <p>The practical consequence: it may fail, skip a turn, or not run at all with nothing bad
 * happening. Which is exactly why it is not allowed to fail the tick that calls it.
 */
@Service
public class SessionCleanupService {

    private static final Logger log = LoggerFactory.getLogger(SessionCleanupService.class);

    /**
     * Attempts are kept <b>twice</b> the window rather than exactly one.
     *
     * <p>A purge cutting flush with the threshold would remove rows a count in progress may be
     * reading, and the only effect would be to lower a counter at the wrong moment — that is,
     * to open a window for whoever is trying passwords.
     */
    private static final Duration ATTEMPT_RETENTION = LoginThrottle.WINDOW.multipliedBy(2);

    private final UserSessions sessions;
    private final LoginAttempts attempts;
    private final MfaChallenges challenges;
    private final Clock clock;

    public SessionCleanupService(
            UserSessions sessions,
            LoginAttempts attempts,
            MfaChallenges challenges,
            Clock clock) {
        this.sessions = sessions;
        this.attempts = attempts;
        this.challenges = challenges;
        this.clock = clock;
    }

    /**
     * @param challenges sign-ins abandoned between the password and the code. {@code
     *     AuthenticationFlowService} sweeps on write, which only clears what a <em>new</em> sign-in
     *     pays for; on an instance nobody signs into, the rows would sit until one did
     */
    public record CleanupResult(int sessions, int attempts, int challenges) {}

    /**
     * Never throws: see the class note.
     *
     * <p>No transaction is opened here. Each statement carries its own — every repository write
     * does, which {@code ArchitectureTest.everyRepositoryWriteIsTransactional} holds — so one
     * failing does not roll back the others, and none is annotated on a method this class calls
     * itself, where the proxy would be bypassed and the annotation would mean nothing.
     */
    public CleanupResult prune() {
        return new CleanupResult(pruneSessions(), pruneAttempts(), pruneChallenges());
    }

    private int pruneSessions() {
        try {
            return sessions.deleteExpired(clock.instant());
        } catch (RuntimeException failed) {
            log.warn("Session purge skipped: {}", failed.getMessage());
            return 0;
        }
    }

    private int pruneChallenges() {
        try {
            return challenges.deleteExpired(clock.instant());
        } catch (RuntimeException failed) {
            log.warn("MFA challenge purge skipped: {}", failed.getMessage());
            return 0;
        }
    }

    private int pruneAttempts() {
        try {
            return attempts.deleteBefore(clock.instant().minus(ATTEMPT_RETENTION));
        } catch (RuntimeException failed) {
            log.warn("Login attempt purge skipped: {}", failed.getMessage());
            return 0;
        }
    }
}
