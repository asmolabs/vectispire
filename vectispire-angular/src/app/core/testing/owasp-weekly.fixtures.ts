import type { OwaspWeek, OwaspWeekCategory, OwaspWeeklyCoverage, OwaspWeeklyScope } from '../api.models';
import { asSchema } from './contract';

/**
 * Weeks of `GET /api/v1/owasp/coverage/weekly`, checked against the published schema.
 *
 * Three weeks by default, and on purpose of both kinds: a reconstructed one first — no state, no
 * settled, an open count that includes settled triage — then two the record captured. A fixture of
 * recorded weeks alone could not tell a screen that paints them alike from one that does not.
 */
export const TITLES: Record<string, string> = {
    A01: 'Broken Access Control',
    A02: 'Cryptographic Failures',
    A03: 'Injection',
    A04: 'Insecure Design',
    A05: 'Security Misconfiguration',
    A06: 'Vulnerable and Outdated Components',
    A07: 'Identification and Authentication Failures',
    A08: 'Software and Data Integrity Failures',
    A09: 'Security Logging and Monitoring Failures',
    A10: 'Server-Side Request Forgery'
};

export function owaspWeek(
    weekStart: string,
    reconstructed: boolean,
    lines: Partial<Record<string, Partial<OwaspWeekCategory>>> = {},
    reopenedKnown = !reconstructed
): OwaspWeek {
    const categories = Object.entries(TITLES).map(([category, title]) => ({
        category,
        title,
        state: reconstructed ? null : ('NOT_COVERED' as const),
        open: 0,
        settled: reconstructed ? null : 0,
        opened: 0,
        resolved: 0,
        reopened: reopenedKnown ? 0 : null,
        ...lines[category]
    }));
    const sum = (pick: (line: OwaspWeekCategory) => number) =>
        categories.reduce((total, line) => total + pick(line), 0);
    return {
        weekStart,
        reconstructed,
        capturedAt: reconstructed ? null : `${weekStart}T06:00:00Z`,
        categoriesMeasured: reconstructed
            ? null
            : categories.filter((line) => line.state === 'FINDINGS' || line.state === 'NO_FINDING').length,
        open: sum((line) => line.open),
        settled: reconstructed ? null : sum((line) => line.settled ?? 0),
        opened: sum((line) => line.opened),
        resolved: sum((line) => line.resolved),
        reopened: reopenedKnown ? sum((line) => line.reopened ?? 0) : null,
        categories
    };
}

export function weeklyCoverage(weeks: OwaspWeek[], scope: OwaspWeeklyScope | null = null): OwaspWeeklyCoverage {
    return asSchema('OwaspWeeklyCoverage', {
        from: weeks[0].weekStart,
        to: weeks[weeks.length - 1].weekStart,
        scope,
        reopenedRecordedFrom: weeks.find((week) => week.reopened !== null)?.weekStart ?? null,
        weeks
    });
}

/**
 * A reconstructed week, then two recorded ones; A06 carries the figures, A03 an unmeasured square.
 * Reopenings are recorded from the second week on: the first one's `reopened` is unknown.
 */
export function threeWeeks(): OwaspWeeklyCoverage {
    return weeklyCoverage([
        owaspWeek('2026-09-14', true, { A06: { open: 9, opened: 2, resolved: 1 } }),
        owaspWeek('2026-09-21', false, {
            A06: { state: 'FINDINGS', open: 4, settled: 3, opened: 1, resolved: 5 },
            A03: { state: 'NOT_MEASURED' },
            A02: { state: 'NO_FINDING' },
            A09: { state: null }
        }),
        owaspWeek('2026-09-28', false, {
            A06: { state: 'FINDINGS', open: 6, settled: 3, opened: 3, resolved: 1, reopened: 2 },
            A03: { state: 'NOT_MEASURED' },
            A02: { state: 'NO_FINDING' }
        })
    ]);
}
