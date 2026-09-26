package com.asmolabs.vectispire.core.access.internal;

import com.asmolabs.vectispire.core.access.SessionCleanupService;
import com.asmolabs.vectispire.core.maintenance.MaintenanceTask;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/**
 * Expired sessions, old sign-in attempts, abandoned MFA challenges and aged gate verdicts, removed.
 */
@Component
@Order(MaintenanceTask.Sequence.SESSION_CLEANUP)
public class SessionCleanupTask implements MaintenanceTask {

    private static final Logger log = LoggerFactory.getLogger(SessionCleanupTask.class);

    private final SessionCleanupService sessions;

    public SessionCleanupTask(SessionCleanupService sessions) {
        this.sessions = sessions;
    }

    @Override
    public Cadence cadence() {
        return Cadence.HOURLY;
    }

    @Override
    public void run() {
        SessionCleanupService.CleanupResult cleaned = sessions.prune();
        if (cleaned.sessions() > 0
                || cleaned.attempts() > 0
                || cleaned.challenges() > 0
                || cleaned.verdicts() > 0) {
            log.info(
                    "Maintenance: {} expired session(s), {} old login attempt(s), {} abandoned "
                            + "MFA challenge(s) and {} aged gate verdict(s) removed.",
                    cleaned.sessions(),
                    cleaned.attempts(),
                    cleaned.challenges(),
                    cleaned.verdicts());
        }
    }
}
