import type { Params } from '@angular/router';
import type {
    OwaspState,
    OwaspWeek,
    OwaspWeekCategory,
    OwaspWeeklyCoverage,
    OwaspWeeklyQuery
} from '@/app/core/api.models';
import type { I18nService } from '@/app/core/i18n/i18n.service';

/**
 * The weekly OWASP view's rules, apart from any screen.
 *
 * Two screens read them: the view itself, which builds the links its figures open, and the backlog,
 * which reads those links back and says what they ask. Written once, so that the day a week's
 * boundary moves the figure and the list it opens move together — a link built in one file and read
 * in another with its own idea of "the week's last day" is a figure that opens a list disagreeing
 * with it.
 *
 * **Every date is an ISO day in UTC**, the cut the server's weeks use (Monday 00:00 UTC to the next,
 * excluded). A week read in the browser's zone would put Sunday evening in Paris into Monday's week.
 */

/** The windows offered, in weeks; the server refuses more than {@link MAX_WEEKS}. */
export const WINDOW_SIZES = [12, 26, 52] as const;
export type WindowSize = (typeof WINDOW_SIZES)[number];
export const DEFAULT_WINDOW: WindowSize = 12;
export const MAX_WEEKS = 52;

export type WeeklyScope = { kind: 'project' | 'solution'; id: number } | null;

export type WeeklyWindow = { kind: 'last'; weeks: WindowSize } | { kind: 'range'; from: string; to: string };

/** What the URL of the weekly view says: a link reproduces the view, scope and selected week included. */
export interface WeeklyView {
    window: WeeklyWindow;
    scope: WeeklyScope;
    /** The Monday of the week whose grid is shown; `null` is the last week of the window. */
    week: string | null;
}

const ISO_DAY = /^\d{4}-\d{2}-\d{2}$/;
const CATEGORY = /^A(0[1-9]|10)$/;

/** An ISO day, or nothing: a garbled date in a link is dropped rather than sent for a 400. */
export function isoDay(value: string | null | undefined): string | null {
    if (!value || !ISO_DAY.test(value)) return null;
    const parsed = new Date(`${value}T00:00:00Z`);
    return Number.isNaN(parsed.getTime()) || parsed.toISOString().slice(0, 10) !== value ? null : value;
}

/**
 * What the backlog's `owasp_category` asks for every category at once: the issues the grid places in
 * one of the ten, whichever — what a week's totals count. Not "no filter": licence and quality
 * findings are in no category, and a total opening the whole backlog would list them too.
 */
export const ANY_CATEGORY = 'any';

/** An OWASP 2021 category code, or {@link ANY_CATEGORY}, or nothing. */
export function owaspCategory(value: string | null | undefined): string | null {
    if (value === ANY_CATEGORY) return ANY_CATEGORY;
    return value && CATEGORY.test(value) ? value : null;
}

export function addDays(day: string, days: number): string {
    const date = new Date(`${day}T00:00:00Z`);
    date.setUTCDate(date.getUTCDate() + days);
    return date.toISOString().slice(0, 10);
}

/** The Monday of a day's ISO week, in UTC. */
export function mondayOf(day: string): string {
    const weekday = new Date(`${day}T00:00:00Z`).getUTCDay();
    return addDays(day, -((weekday + 6) % 7));
}

export function currentMonday(now: Date): string {
    return mondayOf(now.toISOString().slice(0, 10));
}

/**
 * The week's last day, Sunday — what `open_at` names. The server reads `open_at` as "open at the end
 * of that day", the next Monday 00:00 UTC excluded: exactly the instant a week's `open` is counted at.
 */
export function sundayOf(weekStart: string): string {
    return addDays(weekStart, 6);
}

function weeksBetween(from: string, to: string): number {
    return Math.round((Date.parse(`${to}T00:00:00Z`) - Date.parse(`${from}T00:00:00Z`)) / (7 * 86_400_000));
}

function idOf(value: string | null): number | null {
    if (value === null || !/^\d+$/.test(value)) return null;
    const id = Number(value);
    return id > 0 ? id : null;
}

/**
 * The view from its URL.
 *
 * A `week` alone — the backlog's way back — opens the smallest window, ending with the current week,
 * that still holds it, so the reader returns to the column they left; one older than a year opens the
 * year that starts with it.
 */
export function readView(params: { get(name: string): string | null }, now: Date): WeeklyView {
    const projectId = idOf(params.get('project_id'));
    const solutionId = idOf(params.get('solution_id'));
    // The server refuses both; a link carrying both keeps the narrower one.
    const scope: WeeklyScope =
        projectId !== null
            ? { kind: 'project', id: projectId }
            : solutionId !== null
              ? { kind: 'solution', id: solutionId }
              : null;

    const picked = isoDay(params.get('week'));
    const week = picked === null ? null : mondayOf(picked);

    const from = isoDay(params.get('from'));
    const to = isoDay(params.get('to'));
    if (from !== null && to !== null) {
        return { window: { kind: 'range', from: mondayOf(from), to: mondayOf(to) }, scope, week };
    }

    const asked = Number(params.get('weeks'));
    const size = WINDOW_SIZES.find((candidate) => candidate === asked);
    if (size !== undefined || week === null) {
        return { window: { kind: 'last', weeks: size ?? DEFAULT_WINDOW }, scope, week };
    }

    const back = weeksBetween(week, currentMonday(now)) + 1;
    const fits = WINDOW_SIZES.find((candidate) => candidate >= back);
    return fits !== undefined
        ? { window: { kind: 'last', weeks: fits }, scope, week }
        : { window: { kind: 'range', from: week, to: addDays(week, 7 * (MAX_WEEKS - 1)) }, scope, week };
}

/** The view as a URL; a default is left out, so a plain visit reads `?view=weekly`. */
export function viewParams(view: WeeklyView): Params {
    const params: Params = { view: 'weekly' };
    if (view.window.kind === 'range') {
        params['from'] = view.window.from;
        params['to'] = view.window.to;
    } else if (view.window.weeks !== DEFAULT_WINDOW) {
        params['weeks'] = String(view.window.weeks);
    }
    if (view.scope) params[`${view.scope.kind}_id`] = String(view.scope.id);
    if (view.week) params['week'] = view.week;
    return params;
}

/** What the server is asked. "The last N weeks" names its first Monday and leaves the end to the server. */
export function queryOf(view: WeeklyView, now: Date): OwaspWeeklyQuery {
    const query: OwaspWeeklyQuery =
        view.window.kind === 'range'
            ? { from: view.window.from, to: view.window.to }
            : { from: addDays(currentMonday(now), -7 * (view.window.weeks - 1)) };
    if (view.scope?.kind === 'project') query.project_id = view.scope.id;
    if (view.scope?.kind === 'solution') query.solution_id = view.scope.id;
    return query;
}

/**
 * What a square of the heatmap says.
 *
 * **`unknown` is not `no_finding`.** A reconstructed week with nothing open says the issues' dates
 * hold nothing for it, not that a scanner looked and found nothing — whether one looked then was
 * never recorded. Painting it green would be the defect the four states exist to remove, moved
 * into the past. `not_recorded` is a recorded week that holds no line for the category.
 */
export type CellKind = 'findings' | 'no_finding' | 'not_measured' | 'not_covered' | 'not_recorded' | 'unknown';

export interface HeatCell {
    kind: CellKind;
    /** 1 to 4 on `findings`, relative to the window's largest open count; 0 elsewhere. */
    level: number;
    open: number;
    /** Settled triage, apart — never added into `open`. `null` where it is not known. */
    settled: number | null;
    reconstructed: boolean;
}

/** The largest open count of the window: the scale a square is graded on, stated in the legend. */
export function maxOpen(weeks: OwaspWeek[]): number {
    return weeks.reduce((max, week) => week.categories.reduce((inner, line) => Math.max(inner, line.open), max), 0);
}

export function gradeOf(open: number, max: number): number {
    if (open <= 0 || max <= 0) return 0;
    return Math.min(4, Math.max(1, Math.ceil((4 * open) / max)));
}

const RECORDED: Record<OwaspState, CellKind> = {
    FINDINGS: 'findings',
    NO_FINDING: 'no_finding',
    NOT_MEASURED: 'not_measured',
    NOT_COVERED: 'not_covered'
};

export function cellOf(week: OwaspWeek, line: OwaspWeekCategory, max: number): HeatCell {
    if (week.reconstructed) {
        return {
            kind: line.open > 0 ? 'findings' : 'unknown',
            level: gradeOf(line.open, max),
            open: line.open,
            settled: null,
            reconstructed: true
        };
    }
    const kind = line.state === null ? 'not_recorded' : RECORDED[line.state];
    return {
        kind,
        level: kind === 'findings' ? gradeOf(line.open, max) : 0,
        open: line.open,
        settled: line.settled,
        reconstructed: false
    };
}

/**
 * The square's colours, light and dark. Literal classes, written out, so that Tailwind finds them:
 * a class assembled from a level would be purged from the build and render as nothing.
 */
export const CELL_CLASSES: Record<Exclude<CellKind, 'findings'>, string> = {
    no_finding: 'bg-emerald-100 text-emerald-900 dark:bg-emerald-950 dark:text-emerald-200',
    // Amber and not orange in the dark: orange-950 is the red-950 of the lightest findings square, near enough.
    not_measured: 'bg-orange-100 text-orange-900 dark:bg-amber-700 dark:text-amber-50',
    not_covered: 'bg-surface-200 text-surface-700 dark:bg-surface-700 dark:text-surface-200',
    not_recorded: 'bg-transparent text-muted-color',
    unknown: 'bg-surface-100 text-muted-color dark:bg-surface-800'
};

export const FINDINGS_CLASSES = [
    '',
    'bg-red-100 text-red-900 dark:bg-red-950 dark:text-red-100',
    'bg-red-200 text-red-900 dark:bg-red-900 dark:text-red-50',
    'bg-red-400 text-white dark:bg-red-700 dark:text-white',
    'bg-red-600 text-white dark:bg-red-500 dark:text-white'
] as const;

export function cellClass(cell: HeatCell): string {
    return cell.kind === 'findings' ? FINDINGS_CLASSES[Math.max(1, cell.level)] : CELL_CLASSES[cell.kind];
}

/**
 * A square's kind in words, through literal keys (decision 0019): a key built from the value —
 * `'owasp_weekly.cell.' + kind` — is one the i18n check cannot see, and ships raw the day a kind is added.
 */
export function cellLabel(i18n: I18nService, kind: CellKind): string {
    switch (kind) {
        case 'findings':
            return i18n.t('owasp_weekly.cell.findings');
        case 'no_finding':
            return i18n.t('owasp_weekly.cell.no_finding');
        case 'not_measured':
            return i18n.t('owasp_weekly.cell.not_measured');
        case 'not_covered':
            return i18n.t('owasp_weekly.cell.not_covered');
        case 'not_recorded':
            return i18n.t('owasp_weekly.cell.not_recorded');
        case 'unknown':
            return i18n.t('owasp_weekly.cell.unknown');
    }
}

/** A recorded state in the grid's own words; `null` — reconstructed or not recorded — says so. */
export function stateLabel(i18n: I18nService, state: OwaspState | null, reconstructed: boolean): string {
    switch (state) {
        case 'FINDINGS':
            return i18n.t('owasp_grid.state.FINDINGS');
        case 'NO_FINDING':
            return i18n.t('owasp_grid.state.NO_FINDING');
        case 'NOT_MEASURED':
            return i18n.t('owasp_grid.state.NOT_MEASURED');
        case 'NOT_COVERED':
            return i18n.t('owasp_grid.state.NOT_COVERED');
        case null:
            return reconstructed ? i18n.t('owasp_weekly.cell.unknown') : i18n.t('owasp_weekly.cell.not_recorded');
    }
}

/**
 * The figure a link counts: one category's line, or — `null` — the week's total, every category at
 * once, which the backlog filters as {@link ANY_CATEGORY}.
 */
export type CategoryOrTotal = string | null;

function scoped(params: Params, scope: WeeklyScope): Params {
    if (scope) params[`${scope.kind}_id`] = String(scope.id);
    return params;
}

function filterOf(category: CategoryOrTotal): string {
    return category ?? ANY_CATEGORY;
}

/**
 * The backlog that a week's open count counts.
 *
 * **`unsettled` on a recorded week, and only there.** A recorded week's `open` leaves settled triage
 * out, as the grid does; a reconstructed one counts every issue open at its end, whatever its triage.
 * The link carries the figure's own definition, or the list it opens is longer than the number
 * clicked. No `state`: with a date, the server lists every state — the issues open on a past Sunday
 * are mostly resolved since, and the backlog's default `open` would hide them.
 */
export function openLink(week: OwaspWeek, category: string, scope: WeeklyScope): Params {
    const params: Params = { owasp_category: category, open_at: sundayOf(week.weekStart) };
    if (!week.reconstructed) params['unsettled'] = 'true';
    return scoped(params, scope);
}

/**
 * The backlog that a week's total open count counts, or `null` where no list can hold it.
 *
 * **A recorded week's total is the grid's, and the grid counts nothing in a category it does not
 * measure** — nor in one the record holds no line of. Such a category may still hold open issues,
 * which the backlog lists under `any`, so the list would come out longer than the total: no link
 * there, rather than one that disagrees. A reconstructed week counts every placed issue open at its
 * end, as the list does, and keeps its link; so does a recorded week where every category is
 * measured or covered by nothing.
 */
export function totalOpenLink(week: OwaspWeek, scope: WeeklyScope): Params | null {
    const uncounted = week.categories.some((line) => line.state === null || line.state === 'NOT_MEASURED');
    if (!week.reconstructed && uncounted) return null;
    return openLink(week, ANY_CATEGORY, scope);
}

/** The issues a week's "opened" bar counts: first seen from its Monday to its Sunday, both included. */
export function openedLink(week: OwaspWeek, category: CategoryOrTotal, scope: WeeklyScope): Params {
    return scoped(
        {
            owasp_category: filterOf(category),
            first_seen_from: week.weekStart,
            first_seen_to: sundayOf(week.weekStart)
        },
        scope
    );
}

/** The issues a week's "resolved" bar counts: resolved from its Monday to its Sunday, both included. */
export function resolvedLink(week: OwaspWeek, category: CategoryOrTotal, scope: WeeklyScope): Params {
    return scoped(
        { owasp_category: filterOf(category), resolved_from: week.weekStart, resolved_to: sundayOf(week.weekStart) },
        scope
    );
}

/**
 * The issues a week's "reopened" bar counts: a reopening the triage history recorded from its Monday
 * to its Sunday. `null` where the week's figure is unknown — before reopenings were recorded, a list
 * would show the ones that happened to be recorded and read as the figure the week does not have.
 */
export function reopenedLink(week: OwaspWeek, category: CategoryOrTotal, scope: WeeklyScope): Params | null {
    if (week.reopened === null) return null;
    return scoped(
        { owasp_category: filterOf(category), reopened_from: week.weekStart, reopened_to: sundayOf(week.weekStart) },
        scope
    );
}

export interface WeekIndicators {
    week: OwaspWeek;
    previous: OwaspWeek | null;
    /** `null` where there is no previous week, or where the two weeks do not count alike. */
    delta: {
        categoriesMeasured: number | null;
        open: number | null;
        settled: number | null;
        opened: number | null;
        resolved: number | null;
        /** `null` also where either week's figure is unknown — before reopenings were recorded. */
        reopened: number | null;
    };
}

/**
 * The selected week's figures and their movement since the week before.
 *
 * **No delta across the record's first week.** A reconstructed `open` counts settled triage and a
 * recorded one does not, so the difference between the two is the definition changing, not the
 * backlog: the week the record starts would show a fall that never happened. The flows are counted
 * from the dates on both kinds of week, and keep their delta.
 */
export function indicatorsOf(weeks: OwaspWeek[], weekStart: string | null): WeekIndicators | null {
    if (weeks.length === 0) return null;
    const index = weekStart === null ? -1 : weeks.findIndex((candidate) => candidate.weekStart === weekStart);
    const at = index < 0 ? weeks.length - 1 : index;
    const week = weeks[at];
    const previous = at > 0 ? weeks[at - 1] : null;
    const comparable = previous !== null && previous.reconstructed === week.reconstructed;
    const minus = (a: number | null, b: number | null) => (a === null || b === null ? null : a - b);
    return {
        week,
        previous,
        delta: {
            categoriesMeasured: comparable ? minus(week.categoriesMeasured, previous.categoriesMeasured) : null,
            open: comparable ? week.open - previous.open : null,
            settled: comparable ? minus(week.settled, previous.settled) : null,
            opened: previous ? week.opened - previous.opened : null,
            resolved: previous ? week.resolved - previous.resolved : null,
            reopened: previous ? minus(week.reopened, previous.reopened) : null
        }
    };
}

/** The categories the curves show first: those with something open in the window. */
export function categoriesWithFindings(weeks: OwaspWeek[]): string[] {
    const seen = new Set<string>();
    for (const week of weeks) for (const line of week.categories) if (line.open > 0) seen.add(line.category);
    return [...seen].sort();
}

/**
 * A spreadsheet cell, written so it cannot become a formula: a value opening with `=`, `+`, `-` or
 * `@` is run by the spreadsheet that opens the file. The figures here are numbers and codes, but a
 * category title is the server's text, and the rule costs nothing to keep.
 */
function csvCell(value: string | number | boolean | null): string {
    if (value === null) return '';
    let text = String(value);
    if (typeof value === 'string' && /^[=+\-@\t\r]/.test(text)) text = `'${text}`;
    return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

const CSV_HEADER = [
    'week_start',
    'week_end',
    'reconstructed',
    'captured_at',
    'category',
    'title',
    'state',
    'open',
    'settled',
    'opened',
    'resolved',
    'reopened'
];

/**
 * The weekly figures as a CSV, one row per week and category.
 *
 * `reconstructed` is on every row, because it changes what `open` means on that row: a figure
 * copied out of the file without it would be compared with a recorded one it does not count alike.
 * An empty `state`, `settled` or `reopened` is "not known", never zero.
 */
export function weeklyCsv(coverage: OwaspWeeklyCoverage): string {
    const rows = [CSV_HEADER.join(',')];
    for (const week of coverage.weeks) {
        for (const line of week.categories) {
            rows.push(
                [
                    week.weekStart,
                    sundayOf(week.weekStart),
                    week.reconstructed,
                    week.capturedAt,
                    line.category,
                    line.title,
                    line.state,
                    line.open,
                    line.settled,
                    line.opened,
                    line.resolved,
                    line.reopened
                ]
                    .map(csvCell)
                    .join(',')
            );
        }
    }
    return `${rows.join('\r\n')}\r\n`;
}
