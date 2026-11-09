package com.asmolabs.vectispire.common.domain.scheduling;

import java.time.Instant;
import java.util.Optional;

/**
 * A parsed cron expression, reduced to the one question the scheduling rule asks it.
 *
 * <p><b>A port, because parsing cron is a library's job and the scheduling rule is not.</b>
 * The rule — the expression wins over the interval, and a late round catches up rather than
 * skipping — has to stay in the domain, where it is testable without a clock and without a
 * framework. Cron parsing belongs to whatever the control plane already depends on, and Spring
 * ships a perfectly good parser that the domain is not allowed to see.
 *
 * <p>So the domain declares the shape and {@code vectispire-core} supplies it. Tests here pass a
 * lambda, which is also the honest way to write "given that the next occurrence is Tuesday at
 * two" without asserting anything about cron syntax.
 */
@FunctionalInterface
public interface CronSchedule {

    /**
     * The first occurrence strictly after {@code from}, or empty if the expression will never
     * fire again.
     */
    Optional<Instant> nextAfter(Instant from);

    /**
     * A schedule that never fires — what an unusable stored expression becomes.
     *
     * <p>Not {@code null} and not an absent cron: those two mean "this target runs on its
     * interval", and a target whose expression is broken must not quietly start running on a
     * drifting interval the operator did not ask for.
     */
    CronSchedule NEVER = from -> Optional.empty();
}
