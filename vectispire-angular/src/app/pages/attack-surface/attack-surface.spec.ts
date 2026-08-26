import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { AttackSurface } from './attack-surface';

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

    const GLOBAL = {
        totalEndpoints: 40,
        publicEndpoints: 12,
        internalEndpoints: 28,
        unauthenticatedEndpoints: 5,
        shadowEndpoints: 2,
        sensitiveUnprotectedEndpoints: 1,
        frameworks: ['spring', 'express'],
        highRiskEndpoints: []
    };

    const REPO_OVERVIEW = {
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
    };

    beforeEach(async () => {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [AttackSurface],
            providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        fixture = TestBed.createComponent(AttackSurface);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();

        http.expectOne((call) => call.url === '/api/v1/attack-surface').flush(GLOBAL);
        http.expectOne((call) => call.url === '/api/v1/repositories').flush([
            { id: 7, name: 'ours', displayName: 'Ours', url: 'ssh://git@example.invalid/ours.git', branch: 'main' }
        ]);
    }, 20_000);

    it('shows the estate figures until a repository is chosen, then that repository\'s', () => {
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
});
