package com.asmolabs.vectispire.core.access;

import com.asmolabs.vectispire.common.domain.crypto.Digests;
import com.asmolabs.vectispire.core.access.persistence.RateWindowRepository;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.stereotype.Service;

/**
 * A request limit counted by every instance together, in fixed windows, in the database.
 *
 * <p><b>Why the database.</b> The tracker webhook's ceiling was a bucket per address in each
 * instance's memory, so an address behind a load balancer of three instances had three ceilings,
 * and the operator who set three hundred a minute got nine hundred. The database is the one store
 * every instance already shares; a cache that only some deployments have would have made the limit
 * depend on the topology.
 *
 * <p><b>Fixed windows, not a token bucket.</b> A bucket's state is a level and an instant, which one
 * statement cannot update portably; a window's is a count, which one {@code update … set hits = hits
 * + 1} can. The cost is the boundary: a subject can spend its allowance at the end of one window and
 * again at the start of the next, twice the ceiling in a short span. For a limit meant to stop a
 * flood rather than to meter a quota, that is accepted.
 *
 * <p><b>It never admits more than the ceiling, and may refuse a little early.</b> The count is read
 * after the increment, so each caller sees at least its own position: one admitted saw a count
 * within the ceiling, which its own hit is part of. Under contention a caller can read a count raised
 * by others after it and be refused although its hit was within — never the other way round.
 *
 * <p><b>A database failure admits.</b> The request behind the limit needs the database too and will
 * fail on its own; refusing here would add a 429 to an outage, and the in-memory bucket each caller
 * keeps in front of this still bounds one instance.
 */
@Service
public class RateWindows {

    private static final Logger log = LoggerFactory.getLogger(RateWindows.class);

    /** The limits counted here. The key enters every row's key, so it never changes. */
    public enum Limit {
        TICKET_WEBHOOK("webhook");

        private final String key;

        Limit(String key) {
            this.key = key;
        }
    }

    /**
     * @param retryAfter until the window closes, when refused; zero when admitted
     */
    public record Outcome(boolean admitted, Duration retryAfter) {}

    private final RateWindowRepository windows;
    private final Clock clock;

    public RateWindows(RateWindowRepository windows, Clock clock) {
        this.windows = windows;
        this.clock = clock;
    }

    /**
     * Counts one request of {@code subject} against {@code limit}, and says whether it is within
     * {@code ceiling} for the window it falls in.
     *
     * <p><b>No transaction here</b>, deliberately: the first hit of a window is an insert that may
     * lose to another instance's, and on PostgreSQL a failed statement poisons the transaction around
     * it — the increment that follows would be refused. Each statement commits on its own.
     */
    public Outcome hit(Limit limit, String subject, int ceiling, Duration window) {
        Instant now = clock.instant();
        long length = Math.max(1, window.toMillis());
        long number = Math.floorDiv(now.toEpochMilli(), length);
        Instant closes = Instant.ofEpochMilli((number + 1) * length);
        // A digest, not the address: the table is a counter, not a record of who called, and a
        // digest has a width the column can hold whatever the subject's spelling.
        String key = limit.key + ":" + number + ":" + Digests.sha256Hex(subject == null ? "" : subject);
        try {
            if (windows.increment(key) == 0) {
                try {
                    windows.insertFirst(key, closes);
                } catch (DataAccessException anotherInstanceWasFirst) {
                    windows.increment(key);
                }
            }
            int hits = windows.hitsOf(key).orElse(0);
            return hits <= ceiling
                    ? new Outcome(true, Duration.ZERO)
                    : new Outcome(false, Duration.between(now, closes));
        } catch (DataAccessException unavailable) {
            log.warn("The shared {} limit could not be counted, the request is admitted: {}",
                    limit.key, unavailable.getMessage());
            return new Outcome(true, Duration.ZERO);
        }
    }

    /** Drops the windows that have closed — the hourly purge, through {@code SessionCleanupService}. */
    int purgeClosed() {
        return windows.deleteExpired(clock.instant());
    }

    /** Forgets every window of a limit. For the tests, which all deliver from one address. */
    public void forget(Limit limit) {
        windows.deleteByKeyPrefix(limit.key + ":%");
    }
}
