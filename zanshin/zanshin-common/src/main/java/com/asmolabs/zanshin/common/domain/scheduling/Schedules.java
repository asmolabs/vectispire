package com.asmolabs.zanshin.common.domain.scheduling;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

/**
 * When a target is due for a rescan.
 *
 * <p>The interval, the cron expression and the last scheduled time have existed on targets from
 * the start, and the screen collects an interval for every target added. <b>Nothing read
 * them</b>, so every scan was manual — in a tool whose entire premise is that new
 * vulnerabilities appear in code that has not changed. A weekly manual scan is not posture
 * management.
 *
 * <p><b>The cron expression wins over the interval.</b> It is the more specific of the two, and
 * an interval cannot say "every night at two": it drifts a little each round, because the next
 * one is counted from the last, so a scan set for the quiet hours ends up running in the middle
 * of the day. For a job that starts containers and pulls whole registries, the hour is not a
 * detail. Clearing the expression returns the target to its interval.
 *
 * <p>Pure: the policy is tested with no database and no real clock.
 */
public final class Schedules {

    private Schedules() {}

    /**
     * @param cron the parsed expression, when the target has one
     * @param interval how often to rescan otherwise; empty or zero means manual only
     * @param lastScheduledAt when the scheduler last picked this target up, if ever
     */
    public record Schedulable(Optional<CronSchedule> cron, Duration interval, Instant lastScheduledAt) {}

    /** Is this target due, according to the schedule it carries? */
    public static boolean isDue(Schedulable target, Instant now) {
        return target.cron()
                .map(cron -> cronDue(cron, target.lastScheduledAt(), now))
                .orElseGet(() -> intervalDue(target.interval(), target.lastScheduledAt(), now));
    }

    /**
     * Has a target's interval elapsed?
     *
     * <p>A target with no interval is never scheduled — manual only. A target never scanned
     * automatically is <b>due immediately</b>: otherwise switching the scheduler on would leave
     * it waiting a full interval before its first round, which is a day of silence with a daily
     * interval, and reads as a broken scheduler.
     */
    public static boolean intervalDue(Duration interval, Instant lastScheduledAt, Instant now) {
        if (interval == null || interval.isZero() || interval.isNegative()) {
            return false;
        }
        if (lastScheduledAt == null) {
            return true;
        }
        return !now.isBefore(lastScheduledAt.plus(interval));
    }

    /**
     * Has an occurrence passed since the last scheduled round?
     *
     * <p><b>Computed from the last round and not from now</b>, so a round running late — a
     * restart, a slow pass — catches up the occurrence it missed instead of skipping to the
     * next one. A nightly scan must not be lost because the process was restarting at two.
     */
    public static boolean cronDue(CronSchedule cron, Instant lastScheduledAt, Instant now) {
        if (cron == null) {
            return false;
        }
        if (lastScheduledAt == null) {
            // Due immediately — but only once the expression is known to fire at all. Asking
            // that *before* taking the shortcut is what stops the one target whose
            // configuration is broken from being the only one to fire unasked.
            return cron.nextAfter(now).isPresent();
        }
        return cron.nextAfter(lastScheduledAt).map(next -> !next.isAfter(now)).orElse(false);
    }
}
