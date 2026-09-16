import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { Dashboard } from './dashboard';
import { I18nService } from '../../core/i18n/i18n.service';

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

        // **The series names come from the bundle, so the bundle is what the test loads.**
        // Asserting the keys instead would pin that `t()` was called and nothing about whether
        // the key resolves — and an unresolved key renders as itself, which is precisely the
        // failure a reader would see on screen.
        TestBed.inject(I18nService).translations.set({
            dashboard: { chart: { open_backlog: 'Open backlog', opened: 'Opened', resolved: 'Resolved', per_day: 'Per day' } }
        });

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

    it('sépare l\'encours des mouvements, sur deux graphiques et non deux axes', () => {
        flushTrends({
            points: [
                { day: '2026-08-20', open: 5, opened: 2, resolved: 1 },
                { day: '2026-08-21', open: 6, opened: 1, resolved: 0 }
            ],
            mean_days_to_resolve: 3,
            resolved_in_window: 1
        });

        const page = fixture.componentInstance;

        // **Un double axe laissait lire un croisement qui ne veut rien dire** : la position
        // relative des courbes venait du cadrage choisi par la bibliothèque, pas des données.
        expect(page.backlogChart().datasets.map((set) => set.label)).toEqual(['Open backlog']);
        expect(page.backlogChart().datasets[0].data).toEqual([5, 6]);
        expect(page.flowChart().datasets.map((set) => set.label)).toEqual(['Opened', 'Resolved']);
        expect(page.flowChart().datasets[0].data).toEqual([2, 1]);

        // Les mêmes dates, dans le même ordre : c'est ce qui fait des deux panneaux une seule
        // lecture. Un décalage d'un jour entre les deux ferait mentir la superposition.
        expect(page.flowChart().labels).toEqual(page.backlogChart().labels);
    });

    it("ne répète pas les dates d'un graphique à l'autre", () => {
        flushTrends({
            points: [{ day: '2026-08-20', open: 5, opened: 2, resolved: 1 }],
            mean_days_to_resolve: 3,
            resolved_in_window: 1
        });

        const page = fixture.componentInstance;
        // Portées par le graphique du bas seulement : deux jeux de dates l'un sous l'autre
        // répètent la même information et volent la hauteur qui sert à lire les courbes.
        expect(page.backlogOptions().scales.x.ticks.display).toBe(false);
        expect(page.flowOptions().scales.x.ticks.display).toBe(true);
        expect(page.backlogOptions().scales.y.title.text).toBe('Open backlog');
        expect(page.flowOptions().scales.y.title.text).toBe('Per day');
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

    const failing = (rule: string) => ({
        posture: { failingCount: 1, totalCount: 2, kevCount: 1, neverScannedCount: 0, lastScanFailedCount: 0, overdueCount: 0 },
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
            providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        TestBed.inject(I18nService).translations.set({
            dashboard: { chart: { open_backlog: 'Open backlog', opened: 'Opened', resolved: 'Resolved', per_day: 'Per day' } }
        });

        fixture = TestBed.createComponent(Dashboard);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
    }, 20_000);

    it('tags a known-exploited violation as KEV', () => {
        http.expectOne((call) => call.url === '/api/v1/dashboard').flush(failing('kev'));
        fixture.detectChanges();

        expect(fixture.nativeElement.textContent as string).toContain('KEV');
    });

    it('tags anything else as a severity breach', () => {
        http.expectOne((call) => call.url === '/api/v1/dashboard').flush(failing('severity'));
        fixture.detectChanges();

        const text = fixture.nativeElement.textContent as string;
        expect(text).toContain('Severity');
        expect(text).toContain('known exploited');
    });
});
