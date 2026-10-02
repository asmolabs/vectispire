import { convertToParamMap } from '@angular/router';
import { describe, expect, it } from 'vitest';
import { owaspWeek, threeWeeks } from '@/app/core/testing/owasp-weekly.fixtures';
import {
    cellOf,
    gradeOf,
    indicatorsOf,
    maxOpen,
    mondayOf,
    openLink,
    openedLink,
    queryOf,
    readView,
    resolvedLink,
    sundayOf,
    viewParams,
    weeklyCsv
} from './owasp-weekly';

/**
 * The weekly view's rules: what a square says, and what the list it opens is asked.
 *
 * A figure that opens a list disagreeing with it reads as a wrong figure, so the boundaries are
 * pinned to the day: a week is Monday to Sunday in UTC, and its open count is counted at the end of
 * its Sunday.
 */
describe('the weekly OWASP view, as rules', () => {
    const now = new Date('2026-10-02T21:30:00Z'); // a Friday

    it('cuts weeks Monday to Sunday, in UTC', () => {
        expect(mondayOf('2026-10-02')).toBe('2026-09-28');
        expect(mondayOf('2026-09-28')).toBe('2026-09-28');
        expect(mondayOf('2026-10-04')).toBe('2026-09-28');
        expect(sundayOf('2026-09-28')).toBe('2026-10-04');
        // Across a month and a year.
        expect(sundayOf('2025-12-29')).toBe('2026-01-04');
    });

    it('reads the window, the scope and the week from the URL, and writes them back the same', () => {
        const view = readView(convertToParamMap({ weeks: '26', project_id: '12', week: '2026-09-23' }), now);
        expect(view).toEqual({
            window: { kind: 'last', weeks: 26 },
            scope: { kind: 'project', id: 12 },
            week: '2026-09-21'
        });
        expect(viewParams(view)).toEqual({ view: 'weekly', weeks: '26', project_id: '12', week: '2026-09-21' });
        expect(queryOf(view, now)).toEqual({ from: '2026-04-06', project_id: 12 });

        const range = readView(convertToParamMap({ from: '2026-01-07', to: '2026-03-01', solution_id: '3' }), now);
        expect(queryOf(range, now)).toEqual({ from: '2026-01-05', to: '2026-02-23', solution_id: 3 });

        // The default is left out of the URL, and asks the twelve weeks ending with this one.
        const plain = readView(convertToParamMap({}), now);
        expect(viewParams(plain)).toEqual({ view: 'weekly' });
        expect(queryOf(plain, now)).toEqual({ from: '2026-07-13' });
    });

    it('opens, from a week alone, the smallest window that still holds it', () => {
        expect(readView(convertToParamMap({ week: '2026-09-14' }), now).window).toEqual({ kind: 'last', weeks: 12 });
        expect(readView(convertToParamMap({ week: '2026-05-04' }), now).window).toEqual({ kind: 'last', weeks: 26 });
        expect(readView(convertToParamMap({ week: '2025-01-06' }), now).window).toEqual({
            kind: 'range',
            from: '2025-01-06',
            to: '2025-12-29'
        });
    });

    it('drops a garbled date or id rather than sending it', () => {
        const view = readView(convertToParamMap({ week: '2026-02-30', project_id: 'abc', weeks: '13' }), now);
        expect(view).toEqual({ window: { kind: 'last', weeks: 12 }, scope: null, week: null });
    });

    it('paints a recorded square by its state, and grades findings on the window', () => {
        const weeks = threeWeeks().weeks;
        const max = maxOpen(weeks);
        expect(max).toBe(9);
        const recorded = weeks[2];
        const line = (week: typeof recorded, category: string) => week.categories.find((c) => c.category === category)!;

        expect(cellOf(recorded, line(recorded, 'A06'), max)).toEqual({
            kind: 'findings',
            level: 3,
            open: 6,
            settled: 3,
            reconstructed: false
        });
        expect(cellOf(recorded, line(recorded, 'A02'), max).kind).toBe('no_finding');
        expect(cellOf(recorded, line(recorded, 'A03'), max).kind).toBe('not_measured');
        expect(cellOf(recorded, line(recorded, 'A01'), max).kind).toBe('not_covered');
        // A recorded week with no line for the category is not recorded — not "nothing found".
        expect(cellOf(weeks[1], line(weeks[1], 'A09'), max).kind).toBe('not_recorded');
        expect(gradeOf(1, 100)).toBe(1);
        expect(gradeOf(100, 100)).toBe(4);
        expect(gradeOf(0, 100)).toBe(0);
    });

    it('marks a reconstructed square as such, and never calls its zero "nothing found"', () => {
        const week = threeWeeks().weeks[0];
        const max = 9;
        expect(
            cellOf(
                week,
                week.categories.find((c) => c.category === 'A06')!,
                max
            )
        ).toEqual({
            kind: 'findings',
            level: 4,
            open: 9,
            settled: null,
            reconstructed: true
        });
        expect(
            cellOf(
                week,
                week.categories.find((c) => c.category === 'A02')!,
                max
            )
        ).toMatchObject({
            kind: 'unknown',
            reconstructed: true
        });
    });

    it('opens a week open count at its Sunday, leaving settled triage out on a recorded week only', () => {
        const [reconstructed, recorded] = threeWeeks().weeks;
        expect(openLink(recorded, 'A06', { kind: 'project', id: 12 })).toEqual({
            owasp_category: 'A06',
            open_at: '2026-09-27',
            unsettled: 'true',
            project_id: '12'
        });
        // A reconstructed week counts settled triage too: the link must not take it out.
        expect(openLink(reconstructed, 'A06', { kind: 'solution', id: 3 })).toEqual({
            owasp_category: 'A06',
            open_at: '2026-09-20',
            solution_id: '3'
        });
        // Never a state: with a date the server lists every state, and `open` would hide the resolved since.
        expect(openLink(recorded, 'A06', null)).not.toHaveProperty('state');
    });

    it('opens the flows on the week Monday to Sunday, both included', () => {
        const week = threeWeeks().weeks[1];
        expect(openedLink(week, 'A06', null)).toEqual({
            owasp_category: 'A06',
            first_seen_from: '2026-09-21',
            first_seen_to: '2026-09-27'
        });
        expect(resolvedLink(week, 'A06', { kind: 'project', id: 7 })).toEqual({
            owasp_category: 'A06',
            resolved_from: '2026-09-21',
            resolved_to: '2026-09-27',
            project_id: '7'
        });
    });

    it('gives the selected week its figures, and no open delta across the start of the record', () => {
        const weeks = threeWeeks().weeks;
        const last = indicatorsOf(weeks, null)!;
        expect(last.week.weekStart).toBe('2026-09-28');
        expect(last.delta).toEqual({ categoriesMeasured: 0, open: 2, settled: 0, opened: 2, resolved: -4 });

        const first = indicatorsOf(weeks, '2026-09-21')!;
        expect(first.delta.open).toBeNull();
        expect(first.delta.settled).toBeNull();
        expect(first.delta.opened).toBe(-1);
    });

    it('writes one CSV row per week and category, with the reconstructed flag and unknowns empty', () => {
        const csv = weeklyCsv(threeWeeks()).split('\r\n');
        expect(csv[0]).toBe(
            'week_start,week_end,reconstructed,captured_at,category,title,state,open,settled,opened,resolved'
        );
        expect(csv).toHaveLength(1 + 30 + 1);
        expect(csv).toContain('2026-09-14,2026-09-20,true,,A06,Vulnerable and Outdated Components,,9,,2,1');
        expect(csv).toContain(
            '2026-09-28,2026-10-04,false,2026-09-28T06:00:00Z,A06,Vulnerable and Outdated Components,FINDINGS,6,3,3,1'
        );
    });

    it('cannot write a formula into the spreadsheet', () => {
        const week = owaspWeek('2026-09-28', false, { A01: { title: '=HYPERLINK("x")' } });
        const csv = weeklyCsv({ from: week.weekStart, to: week.weekStart, scope: null, weeks: [week] });
        expect(csv).toContain(`"'=HYPERLINK(""x"")"`);
    });
});
