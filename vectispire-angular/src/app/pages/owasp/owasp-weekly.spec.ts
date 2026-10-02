import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { Component } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
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
        // The axis steps on zero: -6, -4, -2, 0, 2, 4 for opened up to 3 and resolved down to 5.
        const y = view.flowOptions().scales.y;
        expect([y.min, y.max, y.ticks.stepSize]).toEqual([-6, 4, 2]);
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
        expect(text).toContain('2026-09-14,2026-09-20,true,,A06,Vulnerable and Outdated Components,,9,,2,1');
    });
});
