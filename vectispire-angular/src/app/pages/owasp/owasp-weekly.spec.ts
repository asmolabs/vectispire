import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { Component } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { Router, provideRouter } from '@angular/router';
import { RouterTestingHarness } from '@angular/router/testing';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { useEnglish } from '@/app/core/testing/english';
import { threeWeeks } from '@/app/core/testing/owasp-weekly.fixtures';
import { addDays, currentMonday } from '@/app/shared/owasp-weekly';
import { OwaspWeekly } from './owasp-weekly';

@Component({ selector: 'zs-nowhere', template: '' })
class Nowhere {}

/**
 * The weekly view, through a real router and the DOM: what it asks is read from the URL, and what a
 * reader clicks is a link whose parameters are the figure's own definition.
 */
describe('the weekly OWASP view', () => {
    let harness: RouterTestingHarness;
    let http: HttpTestingController;
    const page = () => harness.routeNativeElement as HTMLElement;
    const originalClick = HTMLAnchorElement.prototype.click;
    const originalCreate = URL.createObjectURL.bind(URL);

    beforeEach(async () => {
        TestBed.configureTestingModule({
            providers: [
                provideHttpClient(withXhr()),
                provideHttpClientTesting(),
                provideRouter([
                    { path: 'owasp', component: OwaspWeekly },
                    { path: 'issues', component: Nowhere }
                ])
            ]
        });
        useEnglish();
        http = TestBed.inject(HttpTestingController);
        harness = await RouterTestingHarness.create();
    }, 20_000);

    afterEach(() => {
        HTMLAnchorElement.prototype.click = originalClick;
        URL.createObjectURL = originalCreate;
    });

    /** Opens the view and answers its requests; returns the weekly request's parameters. */
    async function open(url: string): Promise<URLSearchParams> {
        await harness.navigateByUrl(url);
        let asked: URLSearchParams | null = null;
        for (const request of http.match(() => true)) {
            if (request.request.url === '/api/v1/owasp/coverage/weekly') {
                asked = new URLSearchParams(request.request.urlWithParams.split('?')[1] ?? '');
                request.flush(threeWeeks());
            } else {
                request.flush({ solutions: [], unfiled: { repositoryCount: 0, containerCount: 0, repositories: [] } });
            }
        }
        await harness.fixture.whenStable();
        harness.detectChanges();
        expect(asked).not.toBeNull();
        return asked!;
    }

    function cell(row: number, column: number): HTMLTableCellElement {
        const rows = page().querySelectorAll('[data-testid="owasp-heatmap"] tbody tr');
        return rows[row].querySelectorAll('td')[column];
    }

    it('asks the window and the scope the URL names', async () => {
        const params = await open('/owasp?view=weekly&weeks=26&project_id=12');
        expect(params.get('from')).toBe(addDays(currentMonday(new Date()), -7 * 25));
        expect(params.get('project_id')).toBe('12');
        expect(params.has('to')).toBe(false);
        expect(params.has('solution_id')).toBe(false);
    });

    it('paints every square by its kind, hatches the reconstructed week, and keeps settled apart', async () => {
        await open('/owasp?view=weekly');
        // Row 5 is A06; columns are the three weeks, oldest first.
        const reconstructed = cell(5, 0);
        expect(reconstructed.dataset['kind']).toBe('findings');
        expect(reconstructed.classList).toContain('zs-hatched');
        expect(reconstructed.querySelector('.zs-settled')).toBeNull();

        const recorded = cell(5, 2);
        expect(recorded.classList).not.toContain('zs-hatched');
        expect(recorded.dataset['level']).toBe('3');
        expect(recorded.querySelector('a')?.textContent?.trim()).toBe('6');
        // The accepted risks are beside the count, never in it.
        expect(recorded.querySelector('.zs-settled')?.textContent).toBe('(3)');
        expect(recorded.querySelector('a')?.getAttribute('aria-label')).toContain('3 settled by triage, apart');

        expect(cell(1, 2).dataset['kind']).toBe('no_finding');
        expect(cell(2, 2).dataset['kind']).toBe('not_measured');
        expect(cell(0, 2).dataset['kind']).toBe('not_covered');
        expect(cell(8, 1).dataset['kind']).toBe('not_recorded');
        expect(cell(1, 0).dataset['kind']).toBe('unknown');
        expect(page().querySelector('[data-testid="weekly-legend"]')?.textContent).toContain(
            'reconstructed from issue dates — accepted risks not separated'
        );
    });

    it('opens an open count on the issues open at the week Sunday, in the same scope', async () => {
        await open('/owasp?view=weekly&solution_id=3');
        const recorded = new URL(cell(5, 1).querySelector('a')!.href);
        expect(recorded.pathname).toBe('/issues');
        expect(Object.fromEntries(recorded.searchParams)).toEqual({
            owasp_category: 'A06',
            open_at: '2026-09-27',
            unsettled: 'true',
            solution_id: '3'
        });
        const reconstructed = new URL(cell(5, 0).querySelector('a')!.href);
        expect(Object.fromEntries(reconstructed.searchParams)).toEqual({
            owasp_category: 'A06',
            open_at: '2026-09-20',
            solution_id: '3'
        });
        // A square with nothing open opens nothing.
        expect(cell(1, 2).querySelector('a')).toBeNull();
    });

    it('shows the last week by default, and the week clicked in its grid, with its flows as links', async () => {
        await open('/owasp?view=weekly');
        const indicators = () => page().querySelector('[data-testid="week-indicators"]')!.textContent;
        expect(indicators()).toContain('Week of 2026-09-28 to 2026-10-04');

        const header = page().querySelectorAll<HTMLButtonElement>('[data-testid="owasp-heatmap"] thead button')[1];
        expect(header.getAttribute('aria-label')).toBe('Show the week of 2026-09-21');
        header.click();
        await harness.fixture.whenStable();
        harness.detectChanges();
        // Picking a week asks nothing new: the figures are already here.
        http.expectNone((call) => call.url === '/api/v1/owasp/coverage/weekly');

        expect(indicators()).toContain('Week of 2026-09-21 to 2026-09-27');
        const grid = page().querySelector('[data-testid="week-grid"]')!;
        const resolved = new URL(grid.querySelector<HTMLAnchorElement>('[data-testid="grid-resolved"]')!.href);
        expect(Object.fromEntries(resolved.searchParams)).toEqual({
            owasp_category: 'A06',
            resolved_from: '2026-09-21',
            resolved_to: '2026-09-27'
        });
        const opened = new URL(grid.querySelector<HTMLAnchorElement>('[data-testid="grid-opened"]')!.href);
        expect(opened.searchParams.get('first_seen_from')).toBe('2026-09-21');
        expect(opened.searchParams.get('first_seen_to')).toBe('2026-09-27');
        // The previous week is reconstructed: no open delta across the start of the record.
        expect(page().textContent).toContain('one of the two is reconstructed');
    });

    it('draws the curves for the categories with findings, and the flows downwards for resolutions', async () => {
        await open('/owasp?view=weekly');
        const view = harness.routeDebugElement!.componentInstance as OwaspWeekly;
        expect(view.curveChart().datasets.map((set) => set.label)).toEqual(['A06', 'Total']);
        expect(view.curveChart().datasets[0].data).toEqual([9, 4, 6]);
        expect(view.flowChart().datasets[1].data).toEqual([-1, -5, -1]);
        // No bar, not a zero, where reopenings were not recorded yet.
        expect(view.flowChart().datasets[2].data).toEqual([null, 0, 2]);
        // The axis steps on zero, and holds the opened and the reopened stacked: 3 + 2 up, 5 down.
        const y = view.flowOptions().scales.y;
        expect([y.min, y.max, y.ticks.stepSize]).toEqual([-6, 6, 2]);
        view.flowChanged('A06');
        expect(view.flowChart().datasets[0].data).toEqual([2, 1, 3]);
    });

    it('exports the figures as a CSV, one row per week and category', async () => {
        await open('/owasp?view=weekly');
        let saved: Blob | null = null;
        let name = '';
        URL.createObjectURL = (blob: Blob | MediaSource) => {
            saved = blob as Blob;
            return 'blob:test';
        };
        HTMLAnchorElement.prototype.click = function click(this: HTMLAnchorElement) {
            name = this.download;
        };
        page().querySelector<HTMLButtonElement>('[data-testid="weekly-csv"] button')!.click();
        expect(name).toBe('vectispire-owasp-weekly-2026-09-14-2026-09-28.csv');
        const text = await saved!.text();
        expect(text.split('\r\n')[0]).toContain('reconstructed');
        expect(text).toContain('2026-09-14,2026-09-20,true,,A06,Vulnerable and Outdated Components,,9,,2,1,');
    });

    it('opens the week totals on every category at once, and no open total the grid did not count whole', async () => {
        await open('/owasp?view=weekly&project_id=4');
        const grid = () => page().querySelector('[data-testid="week-grid"]')!;
        const linkOf = (testId: string) => {
            const anchor = grid().querySelector<HTMLAnchorElement>(`[data-testid="${testId}"]`);
            return anchor ? Object.fromEntries(new URL(anchor.href).searchParams) : null;
        };
        // The last week: recorded, A03 not measured — its open total is the grid's, no list holds it.
        expect(linkOf('total-open')).toBeNull();
        expect(grid().querySelector('[data-testid="grid-total"]')?.textContent).toContain('6');
        expect(linkOf('total-opened')).toEqual({
            owasp_category: 'any',
            first_seen_from: '2026-09-28',
            first_seen_to: '2026-10-04',
            project_id: '4'
        });
        expect(linkOf('total-resolved')).toEqual({
            owasp_category: 'any',
            resolved_from: '2026-09-28',
            resolved_to: '2026-10-04',
            project_id: '4'
        });
        expect(linkOf('total-reopened')).toEqual({
            owasp_category: 'any',
            reopened_from: '2026-09-28',
            reopened_to: '2026-10-04',
            project_id: '4'
        });
        const indicators = page().querySelector('[data-testid="week-indicators"]')!;
        const figure = indicators.querySelector<HTMLAnchorElement>('[data-testid="figure-reopened-link"]')!;
        expect(figure.textContent?.trim()).toBe('2');
        expect(new URL(figure.href).searchParams.get('owasp_category')).toBe('any');
        expect(indicators.querySelector('[data-testid="figure-opened-link"]')).not.toBeNull();
        expect(indicators.querySelector('[data-testid="figure-open-link"]')).toBeNull();

        // The reconstructed week counts every placed issue open at its end, as the list does.
        page().querySelectorAll<HTMLButtonElement>('[data-testid="owasp-heatmap"] thead button')[0].click();
        await harness.fixture.whenStable();
        harness.detectChanges();
        expect(linkOf('total-open')).toEqual({ owasp_category: 'any', open_at: '2026-09-20', project_id: '4' });
    });

    it('shows a reopened figure only where it was recorded, and says from when', async () => {
        await open('/owasp?view=weekly');
        const grid = page().querySelector('[data-testid="week-grid"]')!;
        const a06 = grid.querySelector<HTMLAnchorElement>('[data-testid="grid-reopened"]')!;
        expect(Object.fromEntries(new URL(a06.href).searchParams)).toEqual({
            owasp_category: 'A06',
            reopened_from: '2026-09-28',
            reopened_to: '2026-10-04'
        });
        expect(page().querySelector('[data-testid="reopened-note"]')?.textContent).toContain(
            'Reopenings are recorded from the week of 2026-09-21'
        );

        page().querySelectorAll<HTMLButtonElement>('[data-testid="owasp-heatmap"] thead button')[0].click();
        await harness.fixture.whenStable();
        harness.detectChanges();
        // Unknown, said as unknown: a dash with its reason, no link, and no zero.
        const figure = page().querySelector('[data-testid="figure-reopened"]')!;
        expect(figure.textContent?.trim()).toBe('—');
        expect(figure.querySelector('[aria-label]')?.getAttribute('aria-label')).toContain('not recorded yet');
        expect(page().querySelector('[data-testid="grid-reopened"]')).toBeNull();
        expect(page().querySelector('[data-testid="total-reopened"]')).toBeNull();
    });

    it('opens a total bar on every category, and a reopened bar on its reopenings', async () => {
        await open('/owasp?view=weekly&solution_id=3');
        const view = harness.routeDebugElement!.componentInstance as OwaspWeekly;
        const router = TestBed.inject(Router);
        view.flowSelected({ element: { index: 2, datasetIndex: 0 } });
        await harness.fixture.whenStable();
        expect(router.url).toBe(
            '/issues?owasp_category=any&first_seen_from=2026-09-28&first_seen_to=2026-10-04&solution_id=3'
        );

        await open('/owasp?view=weekly&solution_id=3');
        const again = harness.routeDebugElement!.componentInstance as OwaspWeekly;
        again.flowChanged('A06');
        again.flowSelected({ element: { index: 2, datasetIndex: 2 } });
        await harness.fixture.whenStable();
        expect(router.url).toBe(
            '/issues?owasp_category=A06&reopened_from=2026-09-28&reopened_to=2026-10-04&solution_id=3'
        );

        // A reopened bar of a week before the recording opens nothing.
        await open('/owasp?view=weekly');
        const before = harness.routeDebugElement!.componentInstance as OwaspWeekly;
        before.flowSelected({ element: { index: 0, datasetIndex: 2 } });
        await harness.fixture.whenStable();
        expect(router.url).toBe('/owasp?view=weekly');
        expect(page().textContent).not.toContain('Pick a category');
    });
});
