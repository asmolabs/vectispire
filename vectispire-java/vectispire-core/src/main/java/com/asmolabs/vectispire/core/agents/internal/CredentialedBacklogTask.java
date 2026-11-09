package com.asmolabs.vectispire.core.agents.internal;

import com.asmolabs.vectispire.core.agents.CredentialedBacklog;
import com.asmolabs.vectispire.core.maintenance.MaintenanceTask;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/**
 * Says in the control plane's log that scans needing a credential wait with no executor able to be
 * handed it — see {@link CredentialedBacklog} — every minute the state holds, at most every quarter
 * of an hour.
 *
 * <p><b>A task and not a line in the gauge.</b> The gauge is read when something scrapes it, and an
 * installation that scrapes nothing would never see the line; the claim path is per agent, and
 * cannot tell "this agent is kept" — harmless while a verified agent or the built-in worker takes the
 * scans — from "nobody can take them". Every instance runs it, as every task: each instance's log says
 * it, which is where its operator reads.
 *
 * <p><b>Rate-limited</b>, because a minute-by-minute warning about a state that lasts until somebody
 * updates an agent teaches people to filter the logger out. Said again when the count grows, and
 * once when it falls back to zero, so the last word in the log is the true one.
 */
@Component
@Order(MaintenanceTask.Sequence.CREDENTIALED_BACKLOG)
public class CredentialedBacklogTask implements MaintenanceTask {

    private static final Logger log = LoggerFactory.getLogger(CredentialedBacklogTask.class);

    /** How long a warning about the same state stays said. */
    static final Duration QUIET = Duration.ofMinutes(15);

    /** What a turn has to say. */
    enum Say {
        NOTHING,
        WARNING,
        CLEARED
    }

    private final CredentialedBacklog backlog;
    private final Clock clock;

    private Instant lastWarned;
    private long lastWarnedCount;

    public CredentialedBacklogTask(CredentialedBacklog backlog, Clock clock) {
        this.backlog = backlog;
        this.clock = clock;
    }

    @Override
    public Cadence cadence() {
        return Cadence.SCHEDULING;
    }

    @Override
    public void run() {
        CredentialedBacklog.Unserved unserved = backlog.unserved();
        switch (decide(unserved, clock.instant())) {
            case WARNING -> log.warn("{} scan(s) of repositories carrying a credential are waiting, and no executor able "
                            + "to be handed it serves them (required label: {}). {} Pin a signing key and update a "
                            + "delegated agent, or run a local agent or the built-in worker; the gauge "
                            + "vectispire.scans.credential.unserved counts them.",
                    unserved.scans(),
                    String.join(", ", unserved.labels().stream().map(label -> label.isEmpty() ? "none" : label).toList()),
                    unserved.keptAgents().isEmpty()
                            ? "No enabled agent serves them."
                            : "Enabled agents that would take them but hold no verified sealing key: "
                                    + String.join(", ", unserved.keptAgents()) + ".");
            case CLEARED -> log.info("The scans needing a credential are served again: an executor able to be handed "
                    + "it takes them.");
            case NOTHING -> {
                // Said already, or nothing to say.
            }
        }
    }

    /** Whether this turn speaks, and the memory of what the last one said. One turn at a time. */
    synchronized Say decide(CredentialedBacklog.Unserved unserved, Instant now) {
        if (unserved.scans() == 0) {
            if (lastWarned == null) {
                return Say.NOTHING;
            }
            lastWarned = null;
            lastWarnedCount = 0;
            return Say.CLEARED;
        }
        boolean due = lastWarned == null
                || !now.isBefore(lastWarned.plus(QUIET))
                || unserved.scans() > lastWarnedCount;
        if (!due) {
            return Say.NOTHING;
        }
        lastWarned = now;
        lastWarnedCount = unserved.scans();
        return Say.WARNING;
    }
}
