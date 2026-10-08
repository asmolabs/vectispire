import { provideHttpClient, withXhr } from '@angular/common/http';
import { useEnglish } from '@/app/core/testing/english';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { Dashboard } from './dashboard';
import { I18nService } from '../../core/i18n/i18n.service';
import { asSchema } from '@/app/core/testing/contract';
import type { SecurityGrade } from '../../core/api.models';
import { DATED_MARKER, type MarkerChart } from '../../shared/dated-marker';

/**
 * The backlog trend, and the one figure that must not be rounded to zero.
 *
 * <p>`mean_days_to_resolve` is null when nothing was resolved in the window. Rendered as "0 days"
 * it reads as "everything is fixed the day it appears" — the opposite of "there is nothing to
 * measure", and the flattering one of the two. That is the whole reason the server sends null
 * rather than a number, so it is what this suite pins.
 */
describe('the backlog trend', () => {
    let fixture: ComponentFixture<Dashboard>;
    let http: HttpTestingController;

    const OVERVIEW = asSchema('DashboardOverview', {
        posture: {
            failingCount: 0,
            totalCount: 2,
            kevCount: 0,
            neverScannedCount: 0,
            lastScanFailedCount: 0,
            overdueCount: 0
        },
        backlogBySeverity: {},
        qualityTotal: 0,
        failing: [],
        recentScans: []
    });

    beforeEach(async () => {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [Dashboard],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        // **The series names come from the bundle, so the bundle is what the test loads.**
        // Asserting the keys instead would pin that `t()` was called and nothing about whether
        // the key resolves — and an unresolved key renders as itself, which is precisely the
        // failure a reader would see on screen.
        TestBed.inject(I18nService).translations.set({
            dashboard: {
                chart: { open_backlog: 'Open backlog', opened: 'Opened', resolved: 'Resolved', per_day: 'Per day' }
            }
        });

        useEnglish();
        fixture = TestBed.createComponent(Dashboard);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
        http.expectOne((call) => call.url === '/api/v1/dashboard').flush(OVERVIEW);
    }, 20_000);

    function flushTrends(body: Record<string, unknown>): void {
        http.expectOne((call) => call.url === '/api/v1/dashboard/trends').flush(body);
        fixture.detectChanges();
    }

    it('asks for ninety days by default, as the route does', () => {
        // The default lives in one place; a screen with its own would silently disagree with the
        // window the server documents.
        expect(fixture.componentInstance.window()).toBe(90);
        flushTrends({ points: [], mean_days_to_resolve: null, resolved_in_window: 0 });
    });

    it('names the severity tiles and the windows in words, through keys the i18n check reads', () => {
        flushTrends({ points: [], mean_days_to_resolve: null, resolved_in_window: 0 });
        const component = fixture.componentInstance;

        expect(component.severities().map((tile) => tile.label)).toEqual(['Critical', 'High', 'Medium', 'Low']);
        expect(component.windows().map((choice) => choice.label)).toEqual(['30 days', '90 days', '1 year']);
    });

    it('says there is no measurement rather than showing zero days', () => {
        flushTrends({
            points: [
                { day: '2026-08-20', open: 4, opened: 1, resolved: 0 },
                { day: '2026-08-21', open: 4, opened: 0, resolved: 0 }
            ],
            mean_days_to_resolve: null,
            resolved_in_window: 0
        });

        expect(fixture.componentInstance.meanLabel()).toBe('No measurement');
        expect(fixture.nativeElement.textContent).toContain('Nothing was resolved in this window');
        // Read from the tile and not from the page, whose window buttons legitimately say
        // "30 days". What must never appear is a *measurement* of zero: it would read as "fixed
        // the day it appears" on a window where nothing was fixed at all.
        const tile = fixture.nativeElement.querySelector('#mean-days-to-resolve');
        expect(tile.textContent.trim()).toBe('No measurement');
        expect(tile.textContent).not.toContain('0');
    });

    it('shows the mean with the population it rests on', () => {
        flushTrends({
            points: [{ day: '2026-08-21', open: 7, opened: 2, resolved: 3 }],
            mean_days_to_resolve: 12.42,
            resolved_in_window: 9
        });

        expect(fixture.componentInstance.meanLabel()).toBe('12.4 days');
        // An average with no denominator is a number people quote and should not.
        expect(fixture.nativeElement.textContent).toContain('9 issues resolved');
    });

    it('separates the backlog from the movements, on two charts and not two axes', () => {
        flushTrends({
            points: [
                { day: '2026-08-20', open: 5, opened: 2, resolved: 1 },
                { day: '2026-08-21', open: 6, opened: 1, resolved: 0 }
            ],
            mean_days_to_resolve: 3,
            resolved_in_window: 1
        });

        const page = fixture.componentInstance;

        // **A dual axis let a reader see a crossing that means nothing**: the relative position of
        // the curves came from the framing the library chose, not from the data.
        expect(page.backlogChart().datasets.map((set) => set.label)).toEqual(['Open backlog']);
        expect(page.backlogChart().datasets[0].data).toEqual([5, 6]);
        expect(page.flowChart().datasets.map((set) => set.label)).toEqual(['Opened', 'Resolved']);
        expect(page.flowChart().datasets[0].data).toEqual([2, 1]);

        // The same dates, in the same order: it is what makes the two panels a single reading. A
        // one-day shift between them would make the alignment lie.
        expect(page.flowChart().labels).toEqual(page.backlogChart().labels);
    });

    it('does not repeat the dates from one chart to the other', () => {
        flushTrends({
            points: [{ day: '2026-08-20', open: 5, opened: 2, resolved: 1 }],
            mean_days_to_resolve: 3,
            resolved_in_window: 1
        });

        const page = fixture.componentInstance;
        // Carried by the lower chart only: two sets of dates one under the other repeat the same
        // information and steal the height used to read the curves.
        expect(page.backlogOptions().scales.x.ticks.display).toBe(false);
        expect(page.flowOptions().scales.x.ticks.display).toBe(true);
        expect(page.backlogOptions().scales.y.title.text).toBe('Open backlog');
        expect(page.flowOptions().scales.y.title.text).toBe('Per day');
    });

    it('re-asks the server for another window instead of slicing the series it holds', () => {
        flushTrends({
            points: [{ day: '2026-08-21', open: 1, opened: 0, resolved: 0 }],
            mean_days_to_resolve: null,
            resolved_in_window: 0
        });

        fixture.componentInstance.loadTrends(30);
        const call = http.expectOne((request) => request.url === '/api/v1/dashboard/trends');
        expect(call.request.urlWithParams).toContain('days=30');
        // Cleared while the answer is in flight: a curve left under a new window's label is a
        // chart that says thirty days and shows a year.
        expect(fixture.componentInstance.trends()).toBeNull();
        call.flush(asSchema('Trends', { points: [], mean_days_to_resolve: null, resolved_in_window: 0 }));
    });

    /**
     * The day the scorecard formula changed here (decision 0036). The curves are the backlog's, which
     * the formula does not move; the line is for whoever sets a grade beside them, and the page says
     * the same in words, since a canvas says nothing to a screen reader.
     */
    it('marks the day the score formula changed, on the chart and in words, when it falls in the window', () => {
        flushTrends({
            points: [
                { day: '2026-10-19', open: 5, opened: 2, resolved: 1 },
                { day: '2026-10-20', open: 6, opened: 1, resolved: 0 },
                { day: '2026-10-21', open: 6, opened: 0, resolved: 0 }
            ],
            mean_days_to_resolve: 3,
            resolved_in_window: 1,
            score_formula_changed_on: '2026-10-20'
        });

        const page = fixture.componentInstance;
        expect(page.backlogOptions().plugins.datedMarker).toMatchObject({ index: 1, label: 'Score formula changed' });
        // The lower chart repeats the line, not the label.
        expect(page.flowOptions().plugins.datedMarker).toMatchObject({ index: 1, label: undefined });
        const note = (fixture.nativeElement as HTMLElement).querySelector('[data-testid="score-formula-change"]');
        expect(note?.textContent).toContain('The scorecard formula changed on 2026-10-20 (0.11.0)');
    });

    it('draws no line and says nothing when the change is outside the window, or never happened here', () => {
        flushTrends({
            points: [{ day: '2026-10-21', open: 6, opened: 0, resolved: 0 }],
            mean_days_to_resolve: 3,
            resolved_in_window: 1,
            score_formula_changed_on: '2026-10-20'
        });

        expect(fixture.componentInstance.backlogOptions().plugins.datedMarker.index).toBe(-1);
        expect((fixture.nativeElement as HTMLElement).querySelector('[data-testid="score-formula-change"]')).toBeNull();
    });

    it('says the trend failed instead of drawing an empty history', () => {
        http.expectOne((call) => call.url === '/api/v1/dashboard/trends').flush(null, {
            status: 500,
            statusText: 'Server Error'
        });
        fixture.detectChanges();

        // An empty frame here reads as "no issue was ever opened", which is a statement about the
        // estate rather than about the request.
        expect(fixture.nativeElement.textContent).toContain('Could not load the backlog trend.');
    });
});

/**
 * The tag on a failing target's violation.
 *
 * <p>The row exists to make a KEV stand out — a vulnerability someone is known to be exploiting.
 * The screen reads `violation.rule === 'kev'`, and this route used to send the domain record,
 * whose rule serialises as the enum: `KEV`. Every violation on the dashboard was therefore tagged
 * "Severity", the KEV ones included, and the one row meant to be unmissable read like the others.
 * The route now sends the same spelling as every other; this is what says so from the screen's
 * side.
 */
describe('the failing targets table', () => {
    let fixture: ComponentFixture<Dashboard>;
    let http: HttpTestingController;

    const failing = (rule: string) =>
        asSchema('DashboardOverview', {
            posture: {
                failingCount: 1,
                totalCount: 2,
                kevCount: 1,
                neverScannedCount: 0,
                lastScanFailedCount: 0,
                overdueCount: 0
            },
            backlogBySeverity: { CRITICAL: 1 },
            qualityTotal: 0,
            failing: [
                {
                    kind: 'repository',
                    targetId: 5,
                    name: 'Arm Libs Spring',
                    observed: true,
                    violations: [
                        {
                            rule,
                            issueId: 7,
                            identifier: 'CVE-2026-1234',
                            severity: 'critical',
                            package: 'openssl',
                            fixVersions: '3.0.14',
                            reason: 'known exploited'
                        }
                    ]
                }
            ],
            recentScans: []
        });

    beforeEach(async () => {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [Dashboard],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        TestBed.inject(I18nService).translations.set({
            dashboard: {
                chart: { open_backlog: 'Open backlog', opened: 'Opened', resolved: 'Resolved', per_day: 'Per day' }
            }
        });

        useEnglish();
        fixture = TestBed.createComponent(Dashboard);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
    }, 20_000);

    it('tags a known-exploited violation as KEV', () => {
        http.expectOne((call) => call.url === '/api/v1/dashboard').flush(failing('kev'));
        fixture.detectChanges();

        expect(fixture.nativeElement.textContent as string).toContain('KEV');
    });

    it('tags a target nobody examined as such, and never as a severity', () => {
        // A never-scanned target fails the gate with an `observation` violation; the template read
        // "KEV, or else Severity", which tagged it — and every coverage violation — "Severity".
        http.expectOne((call) => call.url === '/api/v1/dashboard').flush(failing('observation'));
        fixture.detectChanges();

        const text = fixture.nativeElement.textContent as string;
        expect(text).toContain('Not examined');
        expect(text).not.toContain('Severity');
    });

    it('tags a coverage violation as coverage', () => {
        http.expectOne((call) => call.url === '/api/v1/dashboard').flush(failing('coverage'));
        fixture.detectChanges();

        const text = fixture.nativeElement.textContent as string;
        expect(text).toContain('Coverage');
        expect(text).not.toContain('Severity');
    });

    it('links each severity figure to the list with unsettled=true, the clause the figure counts by', () => {
        // The figure leaves settled triage out; a link without the flag opens a list that does
        // not, and "1 critical" arrives on a page of several.
        http.expectOne((call) => call.url === '/api/v1/dashboard').flush(failing('severity'));
        fixture.detectChanges();

        const links = Array.from(
            (fixture.nativeElement as HTMLElement).querySelectorAll<HTMLAnchorElement>('a[href^="/issues"]')
        );
        const severityLinks = links.filter((link) => link.getAttribute('href')!.includes('severity='));
        expect(severityLinks.length).toBeGreaterThan(0);
        for (const link of severityLinks) {
            expect(link.getAttribute('href')).toContain('unsettled=true');
        }
    });

    it('tags anything else as a severity breach', () => {
        http.expectOne((call) => call.url === '/api/v1/dashboard').flush(failing('severity'));
        fixture.detectChanges();

        const text = fixture.nativeElement.textContent as string;
        expect(text).toContain('Severity');
        expect(text).toContain('known exploited');
    });
});

/**
 * A target nobody scanned, on the maturity ranking.
 *
 * <p>The server ranks it last with `NO_DATA` and a null score. Rendered like the others it read
 * "Grade NO_DATA", "/100" and an empty bar — a measured zero, the worst mark on the board, for a
 * target that was never measured. Asserted through the DOM, since that is where the lie was.
 */
describe('the maturity ranking', () => {
    let fixture: ComponentFixture<Dashboard>;
    let http: HttpTestingController;

    const row = (
        targetId: number,
        targetName: string,
        maturityGrade: SecurityGrade,
        securityScore: number | null,
        riskPoints: number | null = null
    ) => ({
        targetId,
        targetKind: 'repository',
        targetName,
        maturityGrade,
        securityScore,
        riskPoints,
        targetMttrDays: null,
        openCritical: 2,
        openHigh: 0,
        openMedium: 0,
        openLow: 0,
        totalResolved: 0
    });

    const ANALYTICS = asSchema('PostureTrendAnalytics', {
        mttrBySeverity: {},
        dailySeries: [],
        overallMttrDays: null,
        netResolutionRatePercentage: 0,
        totalOpenedInWindow: 0,
        totalResolvedInWindow: 0,
        windowDays: 90,
        targetScoreboard: [
            row(3, 'clean-repo', 'A_PLUS', 100, 0),
            row(1, 'graded-repo', 'B', 72, 18.125),
            row(2, 'unscanned-repo', 'NO_DATA', null)
        ]
    });

    beforeEach(async () => {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [Dashboard],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        TestBed.inject(I18nService).translations.set({
            repositories: { grade_tag: 'Grade {{grade}}' },
            dashboard: {
                chart: { open_backlog: 'Open backlog', opened: 'Opened', resolved: 'Resolved', per_day: 'Per day' }
            },
            soa: { measured: { NO_DATA: 'No data' } }
        });

        useEnglish();
        fixture = TestBed.createComponent(Dashboard);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
        // The ranking sits inside the overview's block: without an overview it is not rendered.
        http.expectOne((call) => call.url === '/api/v1/dashboard').flush(
            asSchema('DashboardOverview', {
                posture: {
                    failingCount: 0,
                    totalCount: 2,
                    kevCount: 0,
                    neverScannedCount: 1,
                    lastScanFailedCount: 0,
                    overdueCount: 0
                },
                backlogBySeverity: {},
                qualityTotal: 0,
                failing: [],
                recentScans: []
            })
        );
        http.expectOne((call) => call.url === '/api/v1/dashboard/posture-analytics').flush(ANALYTICS);
        fixture.detectChanges();
    }, 20_000);

    function rowOf(name: string): HTMLTableRowElement {
        const rows = Array.from((fixture.nativeElement as HTMLElement).querySelectorAll<HTMLTableRowElement>('tr'));
        const found = rows.find((tr) => tr.textContent.includes(name));
        expect(found).toBeDefined();
        return found!;
    }

    it('shows no data, and neither a score nor a bar, for a target nobody scanned', () => {
        const tr = rowOf('unscanned-repo');
        expect(tr.querySelector('[data-testid="maturity-no-data"]')?.textContent).toContain('No data');
        expect(tr.textContent).not.toContain('/100');
        expect(tr.textContent).not.toContain('NO_DATA');
        expect(tr.querySelector('[data-testid="maturity-score-bar"]')).toBeNull();
        // The counts are not the score: they stay.
        expect(tr.textContent).toContain('2');
    });

    it('keeps the grade, the score and the bar of a graded target', () => {
        const tr = rowOf('graded-repo');
        expect(tr.textContent).toContain('Grade B');
        expect(tr.textContent).toContain('72/100');
        expect(tr.querySelector<HTMLElement>('[data-testid="maturity-score-bar"]')?.style.width).toBe('72%');
        expect(tr.querySelector('[data-testid="maturity-no-data"]')).toBeNull();
    });

    // What breaks a tie in the order, and what still moves deep in F (decision 0036).
    it('shows the risk points of each graded target, and a dash where there is no grade', () => {
        expect(rowOf('graded-repo').querySelector('[data-testid="maturity-risk-points"]')?.textContent.trim()).toBe(
            '18.125'
        );
        expect(rowOf('clean-repo').querySelector('[data-testid="maturity-risk-points"]')?.textContent.trim()).toBe('0');
        expect(rowOf('unscanned-repo').querySelector('[data-testid="maturity-risk-points"]')?.textContent.trim()).toBe(
            '—'
        );
    });

    it('paints no grade as neutral, not as failing', () => {
        expect(fixture.componentInstance.gradeSeverity('NO_DATA')).toBe('secondary');
        expect(fixture.componentInstance.gradeSeverity('F')).toBe('danger');
    });

    // The ranking grades as the scorecard does, whose best grade is A+: the dashboard's own colours
    // knew A to F only, and painted the best target on the board as failing.
    it('paints a clean scanned target at A+ as the card paints it, not as failing', () => {
        const tr = rowOf('clean-repo');
        expect(tr.textContent).toContain('100/100');
        expect(fixture.componentInstance.gradeSeverity('A_PLUS')).toBe('success');
        expect(tr.querySelector('.p-tag-danger')).toBeNull();
        expect(tr.querySelector('.p-tag-success')).not.toBeNull();
    });

    // The grade used to be printed as its constant: "Grade A_PLUS" at the top of the board.
    it('reads the best grade as A+, not as the name of its constant', () => {
        const tr = rowOf('clean-repo');
        expect(tr.querySelector('.p-tag')?.textContent.trim()).toBe('Grade A+');
        expect(tr.textContent).not.toContain('A_PLUS');
    });
});

/**
 * The dated line itself, drawn on a chart whose canvas is a recording: happy-dom has no canvas, and
 * what matters is where the line stands and that nothing is drawn without a day.
 */
describe('the dated marker', () => {
    function chartRecording() {
        const calls: string[] = [];
        const ctx = new Proxy(
            {},
            {
                get:
                    (_target, name: string) =>
                    (...args: unknown[]) =>
                        calls.push(`${name}(${args.join(',')})`),
                set: () => true
            }
        ) as MarkerChart['ctx'];
        const chart: MarkerChart = {
            ctx,
            chartArea: { top: 10, bottom: 110 },
            scales: { x: { getPixelForValue: (value: number) => 100 + value * 20 } }
        };
        return { chart, calls };
    }

    it('stands on the point of its day, from the top of the plot to its bottom, with its label', () => {
        const { chart, calls } = chartRecording();
        DATED_MARKER.afterDatasetsDraw(chart, {}, { index: 2, label: 'Score formula changed' });

        expect(calls).toContain('moveTo(140,10)');
        expect(calls).toContain('lineTo(140,110)');
        expect(calls).toContain('fillText(Score formula changed,144,21)');
    });

    it('draws nothing without a day in the window', () => {
        const { chart, calls } = chartRecording();
        DATED_MARKER.afterDatasetsDraw(chart, {}, { index: -1, label: 'Score formula changed' });
        DATED_MARKER.afterDatasetsDraw(chart, {}, undefined);

        expect(calls).toEqual([]);
    });
});

/**
 * The portfolio, with no grade of its own (decision 0036): the distribution of the reader's targets
 * over the grades, the weakest by name, and what is open in risk points — read from the DOM, each
 * count with its grade in its accessible name, as a screen reader hears it.
 */
describe('the portfolio', () => {
    let fixture: ComponentFixture<Dashboard>;
    let http: HttpTestingController;

    const PORTFOLIO = asSchema('PortfolioScorecard', {
        totalTargets: 6,
        observedTargets: 5,
        grades: [
            { grade: 'A_PLUS' as const, targets: 3 },
            { grade: 'A' as const, targets: 0 },
            { grade: 'B' as const, targets: 1 },
            { grade: 'C' as const, targets: 0 },
            { grade: 'D' as const, targets: 1 },
            { grade: 'F' as const, targets: 0 },
            { grade: 'NO_DATA' as const, targets: 1 }
        ],
        weakestTarget: {
            targetKind: 'repository',
            targetId: 4,
            targetName: 'payments-api',
            score: 54,
            grade: 'D' as const,
            riskPoints: 29.5
        },
        riskPoints: 40.5,
        openCriticalCount: 2,
        openHighCount: 1,
        openKevCount: 1,
        overdueCount: 0,
        licenseViolationCount: 0
    });

    beforeEach(async () => {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [Dashboard],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();
        useEnglish();
        fixture = TestBed.createComponent(Dashboard);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
        // The panel sits inside the overview's block, as the ranking does.
        http.expectOne((call) => call.url === '/api/v1/dashboard').flush(
            asSchema('DashboardOverview', {
                posture: {
                    failingCount: 0,
                    totalCount: 6,
                    kevCount: 1,
                    neverScannedCount: 1,
                    lastScanFailedCount: 0,
                    overdueCount: 0
                },
                backlogBySeverity: {},
                qualityTotal: 0,
                failing: [],
                recentScans: []
            })
        );
    }, 20_000);

    function load(portfolio: object): HTMLElement {
        http.expectOne((call) => call.url === '/api/v1/scorecards/global').flush(portfolio);
        fixture.detectChanges();
        return fixture.nativeElement as HTMLElement;
    }

    it('counts the targets of each grade, no data included, each count named with its grade', () => {
        const page = load(PORTFOLIO);

        const rows = Array.from(page.querySelectorAll('[data-testid="portfolio-distribution"] li'));
        expect(rows.map((row) => row.getAttribute('aria-label'))).toEqual([
            'Grade A+: 3 targets',
            'Grade A: 0 targets',
            'Grade B: 1 target',
            'Grade C: 0 targets',
            'Grade D: 1 target',
            'Grade F: 0 targets',
            'No data: 1 target'
        ]);
        expect(page.querySelector('[data-testid="portfolio-distribution"]')?.getAttribute('aria-label')).toBe(
            'Targets by grade'
        );
    });

    it('names the weakest target and what is open, and states no single grade for the estate', () => {
        const page = load(PORTFOLIO);

        const weakest = page.querySelector('[data-testid="portfolio-weakest"]')?.textContent ?? '';
        expect(weakest).toContain('payments-api');
        expect(weakest).toContain('Grade D');
        expect(weakest).toContain('54/100');
        expect(page.querySelector('[data-testid="portfolio-risk-points"]')?.textContent).toContain('40.5 risk points');
    });

    it('says no target is scanned yet rather than naming one', () => {
        const page = load({ ...PORTFOLIO, observedTargets: 0, weakestTarget: null });

        expect(page.querySelector('[data-testid="portfolio-weakest"]')?.textContent).toContain(
            'No target scanned yet.'
        );
    });

    it('leaves the panel out for a reader who sees no target', () => {
        const page = load({ ...PORTFOLIO, totalTargets: 0, observedTargets: 0, weakestTarget: null });

        expect(page.querySelector('[data-testid="portfolio-distribution"]')).toBeNull();
    });
});
