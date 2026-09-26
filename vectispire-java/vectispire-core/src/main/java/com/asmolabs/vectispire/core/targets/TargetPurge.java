package com.asmolabs.vectispire.core.targets;

import com.asmolabs.vectispire.common.domain.targets.ScanTarget;

/**
 * Rows that name a target which is going away, to be purged by the domain that owns each table.
 *
 * <p><b>Why an event and not one service deleting every table.</b> Target deletion used to be a
 * single method issuing thirty deletes into the tables of seven domains, so the domain that owns
 * repositories knew the layout of issues, findings, tickets, grants and gate policies. Each owning
 * domain now listens and purges its own rows; the publisher deletes the target itself and knows
 * nobody else's table.
 *
 * <p><b>Synchronous, in the publisher's transaction — never after the commit.</b> The purge and the
 * deletion must be atomic: a target deleted with its issues left behind is an orphan no screen shows,
 * and issues purged for a deletion that then rolled back are triage lost for nothing. Listeners are
 * plain {@code @EventListener}s declaring {@code Propagation.MANDATORY}, so one invoked outside a
 * transaction fails instead of committing its deletes on its own.
 *
 * <p><b>In {@code targets}, which publishes it, since step 5.</b> It sat in {@code vectispire-common}
 * beside {@link ScanTarget} while {@code targets} used {@code scanning} to queue a scan and {@code
 * access} to filter by visibility: owned by {@code targets}, the event would have closed two cycles
 * (decision 0026). {@code targets} now uses {@code access} alone, and asks the scan queue through a
 * port, so every listener sits above it — {@code scanning}, {@code issues}, {@code gate}, {@code
 * inventory}, {@code tickets}, {@code compliance}. The one owner below, {@code access}, is not a
 * listener: {@code TargetDeletionService} revokes the grants by a call, in the same transaction and
 * before the first phase (decision 0029).
 */
public sealed interface TargetPurge permits TargetDeleted, OrphanedTargetRows {

    /**
     * The order the listeners run in, children before parents, so the purge never depends on a
     * cascade the schema declares.
     *
     * <p><b>Why an order at all, when every foreign key into these tables cascades or sets null.</b>
     * On PostgreSQL and MySQL it does — V19 and later — and on SQLite only while {@code PRAGMA
     * foreign_keys} is issued on every connection, which one refactor of the pool can silently
     * undo. Deleting leaves first holds whatever the cascade does, and holds still if a key is ever
     * declared {@code restrict}: a parent deleted before its children would then fail on the two
     * deployable engines and nowhere in the unit suite. Pass these to {@code @Order} on the listener
     * method; listeners of one phase touch disjoint tables and may run in any order among themselves.
     *
     * <p>The graph, as the migrations declare it: {@code t_issue_triage_event} and {@code
     * t_issue_ticket} depend on {@code t_issue}; {@code t_finding} on {@code t_issue} and {@code
     * t_scan}; {@code t_issue} on {@code t_scan} (first and last sighting) and on the target;
     * {@code t_component} and {@code t_ai_review_result} on {@code t_scan}; {@code t_scan} on the
     * target. Grants and gate policies name the target by kind and identifier, with no key at all.
     * {@code t_gate_verdict}, {@code t_api_endpoint} and {@code t_api_contract} are left to the
     * cascade from the target and its scans, as they always were.
     */
    final class Phase {

        /**
         * Rows naming the target by kind and identifier, with no foreign key: gate policies — and the
         * grants, revoked by the publisher itself just before this phase, {@code access} being below
         * {@code targets}.
         */
        public static final int REFERENCES = 100;

        /** What hangs off an issue alone: triage events, ticket links. */
        public static final int ISSUE_CHILDREN = 200;

        /** Findings, which hang off both an issue and a scan. */
        public static final int FINDINGS = 300;

        /** The issues, once nothing refers to them; before the scans they were first and last seen in. */
        public static final int ISSUES = 400;

        /** What hangs off a scan alone: components, AI reviews. */
        public static final int SCAN_CHILDREN = 500;

        /** The scans, last; the publisher deletes the target itself after every listener returned. */
        public static final int SCANS = 600;

        private Phase() {}
    }
}
