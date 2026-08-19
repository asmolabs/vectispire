package com.asmolabs.zanshin.core.services;

import com.asmolabs.zanshin.common.domain.auth.LoginThrottle;
import com.asmolabs.zanshin.core.repositories.LoginAttempts;
import com.asmolabs.zanshin.core.repositories.UserSessions;
import java.time.Clock;
import java.time.Duration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Purging the two authentication tables.
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
    private final Clock clock;

    public SessionCleanupService(UserSessions sessions, LoginAttempts attempts, Clock clock) {
        this.sessions = sessions;
        this.attempts = attempts;
        this.clock = clock;
    }

    public record CleanupResult(int sessions, int attempts) {}

    /**
     * Never throws: see the class note.
     *
     * <p>No transaction is opened here. Each of the two statements carries its own — see the
     * package note on {@code @Modifying} — so one failing does not roll back the other, and
     * neither is annotated on a method this class calls itself, where the proxy would be
     * bypassed and the annotation would mean nothing.
     */
    public CleanupResult prune() {
        return new CleanupResult(pruneSessions(), pruneAttempts());
    }

    private int pruneSessions() {
        try {
            return sessions.deleteExpired(clock.instant());
        } catch (RuntimeException failed) {
            log.warn("Session purge skipped: {}", failed.getMessage());
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
