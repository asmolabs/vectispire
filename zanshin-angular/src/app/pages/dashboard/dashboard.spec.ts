import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { Dashboard } from './dashboard';

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

    const OVERVIEW = {
        posture: { failingCount: 0, totalCount: 2, kevCount: 0, neverScannedCount: 0, lastScanFailedCount: 0, overdueCount: 0 },
        backlogBySeverity: {},
        qualityTotal: 0,
        failing: [],
        recentScans: []
    };

    beforeEach(async () => {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [Dashboard],
            providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

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
        expect(fixture.nativeElement.textContent).toContain('9 issue(s) resolved');
    });

    it('plots the three series the route returns', () => {
        flushTrends({
            points: [
                { day: '2026-08-20', open: 5, opened: 2, resolved: 1 },
                { day: '2026-08-21', open: 6, opened: 1, resolved: 0 }
            ],
            mean_days_to_resolve: 3,
            resolved_in_window: 1
        });

        const chart = fixture.componentInstance.chartData();
        expect(chart.datasets.map((set) => set.label)).toEqual(['Open backlog', 'Opened', 'Resolved']);
        expect(chart.datasets[0].data).toEqual([5, 6]);
        // On the second scale, because the standing backlog and the daily movements differ by two
        // orders of magnitude and one axis would flatten these two onto zero.
        expect(chart.datasets[1].yAxisID).toBe('flows');
        expect(chart.datasets[2].yAxisID).toBe('flows');
    });

    it('re-asks the server for another window instead of slicing the series it holds', () => {
        flushTrends({ points: [{ day: '2026-08-21', open: 1, opened: 0, resolved: 0 }], mean_days_to_resolve: null, resolved_in_window: 0 });

        fixture.componentInstance.loadTrends(30);
        const call = http.expectOne((request) => request.url === '/api/v1/dashboard/trends');
        expect(call.request.urlWithParams).toContain('days=30');
        // Cleared while the answer is in flight: a curve left under a new window's label is a
        // chart that says thirty days and shows a year.
        expect(fixture.componentInstance.trends()).toBeNull();
        call.flush({ points: [], mean_days_to_resolve: null, resolved_in_window: 0 });
    });

    it('says the trend failed instead of drawing an empty history', () => {
        http.expectOne((call) => call.url === '/api/v1/dashboard/trends').flush(null, { status: 500, statusText: 'Server Error' });
        fixture.detectChanges();

        // An empty frame here reads as "no issue was ever opened", which is a statement about the
        // estate rather than about the request.
        expect(fixture.nativeElement.textContent).toContain('Could not load the backlog trend.');
    });
});
