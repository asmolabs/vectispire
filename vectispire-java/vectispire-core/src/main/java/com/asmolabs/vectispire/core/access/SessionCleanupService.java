package com.asmolabs.vectispire.core.access;

import com.asmolabs.vectispire.common.domain.auth.LoginThrottle;
import com.asmolabs.vectispire.common.domain.retention.EvidenceRetention;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.access.persistence.LoginAttempts;
import com.asmolabs.vectispire.core.access.persistence.MfaChallenges;
import com.asmolabs.vectispire.core.access.persistence.UserSessions;
import com.asmolabs.vectispire.core.settings.SettingsService;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Purging the authentication tables, and the evidence other modules hand it through {@link EvidencePurge}.
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
    private final List<EvidencePurge> evidence;
    private final SettingsService settings;
    private final Clock clock;

    public SessionCleanupService(
            UserSessions sessions,
            LoginAttempts attempts,
            MfaChallenges challenges,
            List<EvidencePurge> evidence,
            SettingsService settings,
            Clock clock) {
        this.sessions = sessions;
        this.attempts = attempts;
        this.challenges = challenges;
        this.evidence = evidence;
        this.settings = settings;
        this.clock = clock;
    }

    /**
     * Evidence a module above this one keeps, purged past the evidence window by this pass: the
     * gate's verdict register and the monthly compliance captures.
     *
     * <p><b>A port, because the tables are not this module's.</b> The pass read {@code GateVerdicts}
     * and {@code ComplianceSnapshots} directly while the code was packaged by layer; once {@code gate}
     * owned its register that read closed a cycle, {@code gate} depending on {@code access} for every
     * route it serves. The owners implement this, and the window, its setting and the refusal to fail
     * the tick stay here, where they were.
     */
    public interface EvidencePurge {

        /** Deletes the rows recorded before {@code cutoff} and says how many went. */
        int deleteBefore(Instant cutoff);

        /** What the log line names when this purge is skipped: "Gate verdict", "Compliance snapshot". */
        String label();
    }

    /**
     * @param challenges sign-ins abandoned between the password and the code. {@code
     *     AuthenticationFlowService} sweeps on write, which only clears what a <em>new</em> sign-in
     *     pays for; on an instance nobody signs into, the rows would sit until one did
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
        return new CleanupResult(pruneSessions(), pruneAttempts(), pruneChallenges(),
                evidence.stream().mapToInt(this::pruneEvidence).sum());
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
     * Evidence older than the retention window — gate verdicts, and compliance captures.
     *
     * <p>The captures are counted with the verdicts rather than on a line of their own: both are
     * evidence purged by the same dial, and a result that separated them would invite somebody to
     * give them separate windows — which is the drift the single dial exists to prevent. Each purge
     * is tried apart, as each was before the port: one failing skips its own table, not the other.
     *
     * <p><b>This table grows with the build rate, not with the estate.</b> A pipeline asks the
     * gate on every push, so a busy fortnight writes more rows than a year of scanning does.
     * Without a purge the register that proves the control works becomes the largest table in the
     * database, and the first thing an operator deletes by hand — which destroys the proof.
     *
     * <p><b>It has its own dial, {@code evidence_retention_days}, and no longer follows the payload
     * window.</b> It did at first, on the reasoning that "how far back must we keep things" deserves
     * one answer. It does not: a payload is bulky and reproducible, a verdict is tiny and gone for
     * good. The payload default of ninety days would have emptied this register months before an
     * annual assessment asked to see it — see {@link EvidenceRetention}. Zero purges nothing.
     */
    private int pruneEvidence(EvidencePurge purge) {
        try {
            int days = settings.asInt(Setting.EVIDENCE_RETENTION_DAYS);
            return EvidenceRetention.cutoff(days, clock.instant())
                    .map(purge::deleteBefore)
                    .orElse(0);
        } catch (RuntimeException failed) {
            log.warn("{} purge skipped: {}", purge.label(), failed.getMessage());
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
