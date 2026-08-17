import { CronTime } from 'cron';

/**
 * When a target is due for a rescan.
 *
 * `scanIntervalMinutes`, `scanCron` and `lastScheduledScanAt` have existed on repositories
 * and containers from the start, and the screen collects an interval for every target
 * added. **Nothing read them**, so every scan was manual — in a tool whose entire premise
 * is that *new vulnerabilities appear in code that has not changed*. A weekly manual scan
 * is not posture management.
 *
 * **The cron expression wins over the interval.** It is the more specific of the two, and
 * an interval cannot say "every night at two": it drifts a little each round, because the
 * next one is counted from the last, so a scan set for the quiet hours ends up running in
 * the middle of the day. For a job that starts containers and pulls whole registries, the
 * hour is not a detail. Clearing the expression returns the target to its interval.
 *
 * Pure functions: the policy is tested with no database and no real clock.
 */

/** The expression is not something one can schedule on. */
export class InvalidCronExpression extends Error {}

/**
 * Normalizes an expression, or throws with a message an operator can act on.
 *
 * Called when a target is saved, for the same reason as URL validation: **the point of
 * entry is where a mistake is cheap to fix**. Discovering that an expression was rejected
 * by watching scans *not* happen is the expensive way.
 *
 * Empty means "no cron", which is a valid state: that is how an operator returns to
 * interval scheduling.
 */
export function validateExpression(expression: string | null | undefined): string | null {
    const value = (expression ?? '').trim();
    if (!value) return null;

    try {
        new CronTime(value);
    } catch {
        throw new InvalidCronExpression(
            `Invalid cron expression: "${value}". Expected format: minute hour day month day-of-week — ` +
                'for example "0 2 * * *" (every night at 2 am) or "0 3 * * 1" (every Monday at 3 am).'
        );
    }
    return value;
}

/**
 * Has a target's interval elapsed?
 *
 * A target with no interval is never scheduled (manual only). A target never scanned
 * automatically is **due immediately** — otherwise enabling the scheduler would leave it
 * waiting a whole interval before its first round, which is a day of silence with the
 * 1440-minute default.
 */
export function intervalDue(intervalMinutes: number | null, lastScheduledAt: Date | null, now: Date): boolean {
    if (!intervalMinutes || intervalMinutes <= 0) return false;
    if (lastScheduledAt === null) return true;
    return now.getTime() - lastScheduledAt.getTime() >= intervalMinutes * 60_000;
}

/**
 * Has an occurrence passed since the last scheduled round?
 *
 * **Computed from `lastScheduledAt` and not from `now`**: a round running late — a
 * restart, a slow pass — therefore catches up the occurrence it missed instead of skipping
 * to the next one.
 */
export function cronDue(expression: string, lastScheduledAt: Date | null, now: Date): boolean {
    if (!expression) return false;

    let time: CronTime;
    try {
        time = new CronTime(expression);
    } catch {
        // Checked **before** the "never scheduled" shortcut, and that order matters: an
        // unusable expression would otherwise fire once — the one run nobody asked for,
        // from the one target whose configuration is broken.
        return false;
    }

    if (lastScheduledAt === null) return true;

    return time.getNextDateFrom(lastScheduledAt).toJSDate() <= now;
}

/** What the due check needs. Deliberately narrower than the entities. */
export interface Schedulable {
    scanCron: string | null;
    scanIntervalMinutes: number | null;
    lastScheduledScanAt: Date | null;
}

/** Is this target due, according to the schedule it carries? */
export function isTargetDue(target: Schedulable, now: Date): boolean {
    if (target.scanCron) return cronDue(target.scanCron, target.lastScheduledScanAt, now);
    return intervalDue(target.scanIntervalMinutes, target.lastScheduledScanAt, now);
}
