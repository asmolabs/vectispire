import { InvalidCronExpression, cronDue, intervalDue, isTargetDue, validateExpression } from './due';

const NOW = new Date('2026-08-13T10:00:00.000Z');
const minutesAgo = (minutes: number) => new Date(NOW.getTime() - minutes * 60_000);

describe('intervalDue', () => {
    it("never schedules a target with no interval", () => {
        expect(intervalDue(null, null, NOW)).toBe(false);
        expect(intervalDue(0, null, NOW)).toBe(false);
    });

    it('makes a never-scheduled target due immediately', () => {
        // Otherwise enabling the scheduler would leave the target waiting a whole
        // interval — a day of silence with the 1440-minute default, which the operator
        // would read as a broken scheduler.
        expect(intervalDue(1440, null, NOW)).toBe(true);
    });

    it("waits for the interval to elapse", () => {
        expect(intervalDue(60, minutesAgo(59), NOW)).toBe(false);
        expect(intervalDue(60, minutesAgo(60), NOW)).toBe(true);
    });
});

describe('cronDue', () => {
    it('makes a never-scheduled target due', () => {
        expect(cronDue('0 2 * * *', null, NOW)).toBe(true);
    });

    it("catches up the occurrence a late round missed", () => {
        // Computed from the last round and not from now: a restart must not skip the
        // night.
        expect(cronDue('0 2 * * *', new Date('2026-08-11T02:00:00.000Z'), NOW)).toBe(true);
    });

    it("is not due before the next occurrence", () => {
        expect(cronDue('0 2 * * *', new Date('2026-08-13T02:00:00.000Z'), NOW)).toBe(false);
    });

    it("fires nothing for an unusable expression, even if never scheduled", () => {
        // The order matters: without this check before the shortcut, the one target whose
        // configuration is broken would also be the only one to fire unasked.
        expect(cronDue('n importe quoi', null, NOW)).toBe(false);
        expect(cronDue('', null, NOW)).toBe(false);
    });
});

describe('isTargetDue', () => {
    it("the cron expression wins over the interval", () => {
        // An interval cannot say "every night at two": it drifts, and a scan set for the
        // quiet hours ends up in the middle of the day.
        const target = { scanCron: '0 2 * * *', scanIntervalMinutes: 1, lastScheduledScanAt: new Date('2026-08-13T02:00:00.000Z') };

        expect(isTargetDue(target, NOW)).toBe(false);
    });

    it("falls back to the interval when the expression is cleared", () => {
        const target = { scanCron: null, scanIntervalMinutes: 60, lastScheduledScanAt: minutesAgo(90) };

        expect(isTargetDue(target, NOW)).toBe(true);
    });
});

describe('validateExpression', () => {
    it('accepts a usable expression and normalizes it', () => {
        expect(validateExpression('  0 2 * * *  ')).toBe('0 2 * * *');
    });

    it('treats empty as no cron', () => {
        // That is how an operator returns to interval scheduling.
        expect(validateExpression('')).toBeNull();
        expect(validateExpression(null)).toBeNull();
    });

    it("refuses at the point of entry, with an actionable message", () => {
        // Discovering the rejection by watching scans not happen is the expensive way.
        expect(() => validateExpression('every day')).toThrow(InvalidCronExpression);
        expect(() => validateExpression('99 99 * * *')).toThrow(/Expected format/);
    });
});
