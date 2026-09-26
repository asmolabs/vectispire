package com.asmolabs.vectispire.core.maintenance;

/**
 * One module's share of the periodic housekeeping — the port every domain with a periodic job
 * implements, in its own {@code internal}, and {@code MaintenanceJobs} runs.
 *
 * <p><b>Why a port and not a list of services.</b> The tick named ten services of eight domains, and
 * so sat above all of them: every new job widened a composition root nobody owned, and the class was
 * the reason {@code platform} had to be allowed to use anything. Each module now declares what it
 * needs run, beside the service it calls; this module knows none of them (decision 0029).
 *
 * <p><b>Only work that tolerates being run twice.</b> No leader election happens here: every instance
 * runs every task. A task that must run once — scheduling scans — elects inside the service it calls
 * ({@code SchedulerService} holds the lease), and a task that delivers something claims each item
 * first ({@code OutboxService.relay}). That the relay "was idempotent" was once written here while
 * every instance delivered every message, which is why the mechanism has to be named.
 *
 * <p><b>A composition that is not exercised is not wired.</b> {@code IssueTriageService.expireStale}
 * was called by nothing while its javadoc said "called from the maintenance tick". {@code
 * MaintenanceJobsTest} asserts the tasks the running application contributes, one by one, and what
 * each calls; a task added without it leaves that test red.
 */
public interface MaintenanceTask {

    /**
     * How often the task runs. Three turns, each with its own interval and its own guard, because
     * a single one would have to run at the shortest of the three.
     */
    enum Cadence {
        /**
         * Every {@code vectispire.jobs.relay-interval} (one minute): the shortest retry delay of the
         * backoff policy, so a slower turn would make a due message wait longer than intended.
         */
        RELAY("notification relay"),
        /** Every {@code vectispire.jobs.scheduler-interval} (one minute). */
        SCHEDULING("scheduling tick"),
        /**
         * Every {@code vectispire.jobs.maintenance-interval} (one hour): the purges walk tables that
         * only change at the rate scans happen, and a query every fifteen seconds would find nothing.
         */
        HOURLY("maintenance");

        private final String label;

        Cadence(String label) {
            this.label = label;
        }

        /** How the turn names itself when it fails. */
        public String label() {
            return label;
        }
    }

    /**
     * The order of the hourly turn, for {@code @Order}: the tasks ran in this sequence when they were
     * one method, and two of the positions matter. The triage decisions expire before the weekly
     * digest and the compliance capture read the backlog, so neither reports an acceptance that
     * lapsed an hour ago; the orphaned rows go last, after everything that could still name them.
     * The gaps leave room for a task to be placed without renumbering. The relay and the scheduling
     * tick have turns of their own and are placed first only so that the list the tick receives has
     * one order, which {@code MaintenanceCompositionTest} can compare.
     */
    final class Sequence {
        public static final int NOTIFICATION_RELAY = 10;
        public static final int SCHEDULING_TICK = 20;
        public static final int SCAN_RETENTION = 100;
        public static final int SENT_MESSAGES = 200;
        public static final int TICKET_SWEEP = 300;
        public static final int INVENTORY_BACKFILL = 400;
        public static final int TRIAGE_EXPIRY = 500;
        public static final int WEEKLY_DIGEST = 600;
        public static final int COMPLIANCE_HISTORY = 700;
        public static final int SESSION_CLEANUP = 800;
        public static final int GATE_VERDICTS = 810;
        public static final int COMPLIANCE_SNAPSHOTS = 820;
        public static final int ORPHANED_TARGET_ROWS = 900;

        private Sequence() {}
    }

    Cadence cadence();

    /** Runs once. What it throws ends its turn, is logged, and does not stop the next turn. */
    void run();
}
