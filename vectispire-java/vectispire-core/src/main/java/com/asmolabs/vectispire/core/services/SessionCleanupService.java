package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.auth.LoginThrottle;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.repositories.GateVerdicts;
import com.asmolabs.vectispire.core.repositories.LoginAttempts;
import com.asmolabs.vectispire.core.repositories.MfaChallenges;
import com.asmolabs.vectispire.core.repositories.UserSessions;
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
    private final MfaChallenges challenges;
    private final GateVerdicts verdicts;
    private final SettingsService settings;
    private final Clock clock;

    public SessionCleanupService(
            UserSessions sessions,
            LoginAttempts attempts,
            MfaChallenges challenges,
            GateVerdicts verdicts,
            SettingsService settings,
            Clock clock) {
        this.sessions = sessions;
        this.attempts = attempts;
        this.challenges = challenges;
        this.verdicts = verdicts;
        this.settings = settings;
        this.clock = clock;
    }

    /**
     * @param challenges sign-ins abandoned between the password and the code. {@code AuthController}
     *     sweeps on write, which only clears what a <em>new</em> sign-in pays for; on an instance
     *     nobody signs into, the rows would sit until one did
     */
    public record CleanupResult(int sessions, int attempts, int challenges, int verdicts) {}

    /**
     * Never throws: see the class note.
     *
     * <p>No transaction is opened here. Each of the two statements carries its own — see the
     * package note on {@code @Modifying} — so one failing does not roll back the other, and
     * neither is annotated on a method this class calls itself, where the proxy would be
     * bypassed and the annotation would mean nothing.
     */
    public CleanupResult prune() {
        return new CleanupResult(pruneSessions(), pruneAttempts(), pruneChallenges(), pruneVerdicts());
    }

    private int pruneSessions() {
        try {
            return sessions.deleteExpired(clock.instant());
        } catch (RuntimeException failed) {
            log.warn("Session purge skipped: {}", failed.getMessage());
            return 0;
        }
    }

    /**
     * Gate verdicts older than the retention window.
     *
     * <p><b>This table grows with the build rate, not with the estate.</b> A pipeline asks the
     * gate on every push, so a busy fortnight writes more rows than a year of scanning does.
     * Without a purge the register that proves the control works becomes the largest table in the
     * database, and the first thing an operator deletes by hand — which destroys the proof.
     *
     * <p>It reuses {@code retention_max_age_days}, the window an operator has already chosen for
     * scan payloads, rather than adding a second dial. How far back evidence must reach is one
     * question, and it deserves one answer.
     */
    private int pruneVerdicts() {
        try {
            int days = Math.max(1, settings.asInt(Setting.RETENTION_MAX_AGE_DAYS));
            return verdicts.deleteBefore(clock.instant().minus(Duration.ofDays(days)));
        } catch (RuntimeException failed) {
            log.warn("Gate verdict purge skipped: {}", failed.getMessage());
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
