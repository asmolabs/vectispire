package com.asmolabs.vectispire.core.tickets.internal;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import org.springframework.stereotype.Component;

/**
 * Which refused webhook deliveries earn an audit entry.
 *
 * <p><b>The defect.</b> Every refused call to the anonymous tracker webhook wrote a row into the
 * audit log — hash-chained, never purged — so anybody who could reach the route could write to the
 * log as fast as they could send, burying every entry around theirs. The refusals still matter: a
 * stream of them is somebody probing, or a tracker configured with the wrong secret. So they are
 * recorded the way {@code BearerRateLimitFilter} records refused bearers, sparingly:
 * <ul>
 *   <li>the <b>first</b> refusal from an address in a window, so a single misconfigured tracker is
 *       still visible;
 *   <li>once more when that address reaches the <b>ceiling</b> within the window, which is what
 *       turns "a mistake" into "a sweep";
 *   <li>and never more than a fixed number of entries per window across every address, with one
 *       entry saying so when that budget runs out — an address map does not bound a client that
 *       rotates addresses, and IPv6 gives one plenty.
 * </ul>
 *
 * <p>In memory, per instance: a restart or a second instance each start their own window, which
 * costs at most a few more entries and no lost refusal — the tracker is still answered 401 or 403
 * every time. The address map is bounded like the rate limiters', and for the same reason.
 */
@Component
public class WebhookRefusals {

    static final Duration WINDOW = Duration.ofMinutes(10);

    /** Refusals from one address within a window that earn the second entry. */
    static final int CEILING = 20;

    /** Entries written per window, every address together. */
    static final int GLOBAL_BUDGET = 100;

    private static final int MAX_ADDRESSES = 10_000;

    private final Clock clock;

    private final Map<String, Tally> tallies = Collections.synchronizedMap(
            new LinkedHashMap<>(16, 0.75f, true) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<String, Tally> eldest) {
                    return size() > MAX_ADDRESSES;
                }
            });

    private Instant budgetWindowStart = Instant.EPOCH;
    private int budgetSpent;

    public WebhookRefusals(Clock clock) {
        this.clock = clock;
    }

    private static final class Tally {
        private final Instant start;
        private int count;

        Tally(Instant start) {
            this.start = start;
        }
    }

    /**
     * Counts one refusal, and says whether it is to be audited.
     *
     * @return what to append to the entry's description, or empty when no entry is to be written
     */
    public synchronized Optional<String> refused(String address) {
        Instant now = clock.instant();
        String key = address == null ? "" : address;

        Tally tally = tallies.get(key);
        if (tally == null || !now.isBefore(tally.start.plus(WINDOW))) {
            tally = new Tally(now);
            tallies.put(key, tally);
        }
        tally.count++;

        String note;
        if (tally.count == 1) {
            note = " (first in " + WINDOW.toMinutes() + " min from this address; more are counted, not recorded)";
        } else if (tally.count == CEILING) {
            note = " (" + CEILING + " refusals from this address in " + WINDOW.toMinutes() + " min)";
        } else {
            return Optional.empty();
        }
        return spend(now, note);
    }

    private Optional<String> spend(Instant now, String note) {
        if (!now.isBefore(budgetWindowStart.plus(WINDOW))) {
            budgetWindowStart = now;
            budgetSpent = 0;
        }
        if (budgetSpent >= GLOBAL_BUDGET) {
            return Optional.empty();
        }
        budgetSpent++;
        return Optional.of(budgetSpent == GLOBAL_BUDGET
                ? note + "; webhook refusals are not recorded again for " + WINDOW.toMinutes() + " min"
                : note);
    }

    /** Forgets every count. For the tests. */
    public synchronized void reset() {
        tallies.clear();
        budgetWindowStart = Instant.EPOCH;
        budgetSpent = 0;
    }
}
