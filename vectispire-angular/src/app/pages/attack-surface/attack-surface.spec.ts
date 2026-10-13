import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { useEnglish } from '@/app/core/testing/english';
import { AttackSurface } from './attack-surface';
import { asSchema } from '@/app/core/testing/contract';

/**
 * The attack-surface screen, and the two things it gets wrong quietly.
 *
 * <p>The figures on this page are an exposure count. A stat that keeps showing the estate's
 * numbers under one repository's heading understates or overstates that repository's exposure
 * without looking broken, and a filter that drops an unauthenticated endpoint hides the row the
 * screen exists to surface.
 */
describe('the attack surface screen', () => {
    let fixture: ComponentFixture<AttackSurface>;
    let http: HttpTestingController;

    const endpoint = (
        id: number,
        method: string,
        path: string,
        authRequired: boolean,
        visibility: 'PUBLIC' | 'INTERNAL' | 'UNKNOWN'
    ) => ({
        id,
        scanId: 1,
        repositoryId: 7,
        method,
        path,
        authRequired,
        authType: authRequired ? 'bearer' : null,
        visibility,
        filePath: 'src/main/java/Controller.java',
        lineNumber: 10,
        framework: 'spring',
        operationId: null,
        summary: null,
        tags: null,
        shadowStatus: 'DOCUMENTED' as const,
        createdAt: '2026-08-26T00:00:00Z'
    });

    const GLOBAL = asSchema('GlobalAttackSurface', {
        totalEndpoints: 40,
        publicEndpoints: 12,
        internalEndpoints: 28,
        unauthenticatedEndpoints: 5,
        shadowEndpoints: 2,
        sensitiveUnprotectedEndpoints: 1,
        frameworks: ['spring', 'express'],
        highRiskEndpoints: []
    });

    const REPO_OVERVIEW = asSchema('RepositoryApisOverview', {
        repositoryId: 7,
        endpoints: [
            endpoint(1, 'GET', '/api/admin/users', false, 'PUBLIC'),
            endpoint(2, 'POST', '/api/admin/users', true, 'PUBLIC'),
            endpoint(3, 'GET', '/api/health', false, 'INTERNAL')
        ],
        contracts: [],
        summary: {
            totalEndpoints: 3,
            publicEndpoints: 2,
            internalEndpoints: 1,
            unauthenticatedEndpoints: 2,
            shadowEndpoints: 0,
            sensitiveUnprotectedEndpoints: 1
        }
    });

    beforeEach(async () => {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [AttackSurface],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        fixture = TestBed.createComponent(AttackSurface);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();

        http.expectOne((call) => call.url === '/api/v1/attack-surface').flush(GLOBAL);
        http.expectOne((call) => call.url === '/api/v1/repositories').flush([
            { id: 7, name: 'ours', displayName: 'Ours', url: 'ssh://git@example.invalid/ours.git', branch: 'main' }
        ]);
    }, 20_000);

    it("shows the estate figures until a repository is chosen, then that repository's", () => {
        const page = fixture.componentInstance;
        expect(page.currentStats().totalEndpoints).toBe(40);
        expect(page.currentStats().frameworks).toEqual(['spring', 'express']);

        page.onSelectRepo(7);
        http.expectOne((call) => call.url === '/api/v1/repositories/7/apis').flush(REPO_OVERVIEW);

        // The whole point of selecting a target. Keeping 40 here would put the estate's exposure
        // under one repository's name, which reads as that repository being far worse than it is.
        expect(page.currentStats().totalEndpoints).toBe(3);
        expect(page.currentStats().sensitiveUnprotectedEndpoints).toBe(1);
        // Frameworks are derived from the endpoints rather than taken from the summary, and
        // deduplicated: three endpoints, one framework.
        expect(page.currentStats().frameworks).toEqual(['spring']);
    });

    it('lists nothing until a repository is chosen, rather than everything', () => {
        // An empty list here is deliberate: the endpoint table belongs to one target, and
        // defaulting to the estate's would be the same disclosure the API routes were corrected for.
        expect(fixture.componentInstance.filteredEndpoints()).toEqual([]);
    });

    it('combines the method and authentication filters', () => {
        const page = fixture.componentInstance;
        page.onSelectRepo(7);
        http.expectOne((call) => call.url === '/api/v1/repositories/7/apis').flush(REPO_OVERVIEW);

        expect(page.filteredEndpoints()).toHaveLength(3);

        page.filterAuth.set('UNAUTH');
        expect(page.filteredEndpoints().map((e) => e.id)).toEqual([1, 3]);

        // Both at once: /api/admin/users appears twice, once per method, and only the GET is
        // unauthenticated. A page that applied one filter instead of both would keep the POST.
        page.filterMethod.set('GET');
        expect(page.filteredEndpoints().map((e) => e.path)).toEqual(['/api/admin/users', '/api/health']);

        page.filterVisibility.set('PUBLIC');
        expect(page.filteredEndpoints().map((e) => e.id)).toEqual([1]);
    });

    it('searches the path, and does not ask the server to do it', () => {
        const page = fixture.componentInstance;
        page.onSelectRepo(7);
        http.expectOne((call) => call.url === '/api/v1/repositories/7/apis').flush(REPO_OVERVIEW);

        page.searchQuery.set('HEALTH');
        // Case-insensitive, and local: no request is issued, which is why typing is not throttled.
        expect(page.filteredEndpoints().map((e) => e.id)).toEqual([3]);
        http.expectNone(() => true);
    });

    it('clearing the selection drops the overview instead of refetching it', () => {
        const page = fixture.componentInstance;
        page.onSelectRepo(7);
        http.expectOne((call) => call.url === '/api/v1/repositories/7/apis').flush(REPO_OVERVIEW);

        page.onSelectRepo('ALL');
        expect(page.selectedRepoId()).toBeNull();
        expect(page.repoOverview()).toBeNull();
        expect(page.repoLoading()).toBe(false);
        http.expectNone(() => true);
    });

    function clickRefresh(): void {
        const refresh = Array.from((fixture.nativeElement as HTMLElement).querySelectorAll('button')).find((b) =>
            b.textContent.includes('Refresh')
        );
        expect(refresh).toBeDefined();
        refresh!.click();
        fixture.detectChanges();
    }

    it("says why the repository list is missing, in the server's words", () => {
        useEnglish();
        fixture.detectChanges();
        clickRefresh();
        http.expectOne((call) => call.url === '/api/v1/attack-surface').flush(GLOBAL);
        http.expectOne((call) => call.url === '/api/v1/repositories').flush(
            { detail: 'The inventory is being rebuilt.', status: 503 },
            { status: 503, statusText: 'Service Unavailable' }
        );
        fixture.detectChanges();

        // Swallowed, it left the picker empty and the reader with no reason.
        expect((fixture.nativeElement as HTMLElement).textContent).toContain('The inventory is being rebuilt.');
    });

    it('a second load cancels the first instead of racing it', () => {
        // The refresh button disables itself while loading; a purge reloads whatever is in flight.
        fixture.componentInstance.loadData();
        fixture.componentInstance.loadData();

        const surfaces = http.match((call) => call.url === '/api/v1/attack-surface');
        const lists = http.match((call) => call.url === '/api/v1/repositories');
        expect(surfaces.map((call) => call.cancelled)).toEqual([true, false]);
        expect(lists.map((call) => call.cancelled)).toEqual([true, false]);
        surfaces[1].flush(GLOBAL);
        lists[1].flush([]);
    });

    /**
     * The wait after a scan is launched. It used to poll the figures every three seconds and stop at
     * the first tick that found an endpoint: on an estate that already had forty, at once, announcing
     * "discovery complete" for a scan that was only queued — and every tick sent two requests and
     * blanked the tables. What ends it now is the scan's status, read from the repository list.
     *
     * <p>Through the component: no button on this screen calls `triggerScan` today, so there is no
     * DOM path to the launch; what the reader sees afterwards is read from the DOM.
     */
    describe('after a scan is launched', () => {
        const repositoryWith = (status: string) => [
            {
                id: 7,
                name: 'ours',
                displayName: 'Ours',
                url: 'ssh://git@example.invalid/ours.git',
                branch: 'main',
                lastScan: { id: 90, status, createdAt: '2026-10-13T08:00:00Z', error: null }
            }
        ];
        const text = () => (fixture.nativeElement as HTMLElement).textContent;

        beforeEach(() => {
            vi.useFakeTimers();
            useEnglish();
            fixture.componentInstance.onSelectRepo(7);
            http.expectOne((call) => call.url === '/api/v1/repositories/7/apis').flush(REPO_OVERVIEW);
            fixture.componentInstance.triggerScan();
            http.expectOne((call) => call.url === '/api/v1/repositories/7/scan').flush({ id: 90, status: 'pending' });
            fixture.detectChanges();
        });

        afterEach(() => vi.useRealTimers());

        it('waits for the scan to finish before announcing anything, without reloading the figures meanwhile', () => {
            vi.advanceTimersByTime(3000);
            http.expectOne((call) => call.url === '/api/v1/repositories').flush(repositoryWith('scanning'));
            fixture.detectChanges();

            // Forty endpoints were already listed: the old loop stopped here and announced success.
            expect(text()).not.toContain('API discovery complete');
            expect(text()).toContain('Scan scheduled');
            http.expectNone((call) => call.url === '/api/v1/attack-surface');
            expect(fixture.componentInstance.loading()).toBe(false);

            vi.advanceTimersByTime(3000);
            http.expectOne((call) => call.url === '/api/v1/repositories').flush(repositoryWith('completed'));
            fixture.detectChanges();
            // The reload after the scan is a background one: the tables do not blank under the reader.
            expect(fixture.componentInstance.loading()).toBe(false);
            http.expectOne((call) => call.url === '/api/v1/attack-surface').flush({ ...GLOBAL, totalEndpoints: 43 });
            http.expectOne((call) => call.url === '/api/v1/repositories').flush(repositoryWith('completed'));
            http.expectOne((call) => call.url === '/api/v1/repositories/7/apis').flush(REPO_OVERVIEW);
            fixture.detectChanges();

            expect(text()).toContain('API discovery complete (43 routes listed).');

            // Settled: the timer stops by itself.
            vi.advanceTimersByTime(30_000);
            http.expectNone(() => true);
        });

        it('says the scan failed rather than announcing a discovery', () => {
            vi.advanceTimersByTime(3000);
            http.expectOne((call) => call.url === '/api/v1/repositories').flush(repositoryWith('failed'));
            fixture.detectChanges();
            http.expectOne((call) => call.url === '/api/v1/attack-surface').flush(GLOBAL);
            http.expectOne((call) => call.url === '/api/v1/repositories').flush(repositoryWith('failed'));
            http.expectOne((call) => call.url === '/api/v1/repositories/7/apis').flush(REPO_OVERVIEW);
            fixture.detectChanges();

            expect(text()).toContain('1 scan did not complete');
            expect(text()).not.toContain('API discovery complete');
            vi.advanceTimersByTime(30_000);
            http.expectNone(() => true);
        });
    });
});
