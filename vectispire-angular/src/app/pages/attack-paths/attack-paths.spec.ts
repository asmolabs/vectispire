import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { AttackPaths } from './attack-paths';

/**
 * The attack path screen, and the filter that decides what an operator is shown.
 *
 * **This page arrived without a spec**, which is how sixteen of twenty-nine pages are. It is worth
 * one more than most: the graph it draws is a route from an exposed endpoint to a secret, so a
 * filter that hides the wrong column understates an exposure rather than merely looking wrong.
 */
describe('the attack path graph', () => {
    let fixture: ComponentFixture<AttackPaths>;
    let http: HttpTestingController;

    const REPOSITORIES = [{ id: 7, name: 'exposed', url: 'ssh://git@example.invalid/exposed.git', branch: 'main' }];

    const GRAPH = {
        targetId: 7,
        targetName: 'exposed',
        totalPaths: 1,
        criticalExploitablePaths: 1,
        riskScore: 85,
        nodes: [
            { id: 'ingress-ext', label: 'Internet Ingress (0.0.0.0/0)', type: 'INTERNET_INGRESS', severity: 'INFO', isExploitable: true, subtitle: '', metadata: {} },
            { id: 'ep-1', label: 'GET /api/admin/users', type: 'API_ENDPOINT', severity: 'CRITICAL', isExploitable: true, subtitle: '', metadata: {} },
            { id: 'ep-2', label: 'GET /api/health', type: 'API_ENDPOINT', severity: 'MEDIUM', isExploitable: false, subtitle: '', metadata: {} },
            { id: 'vuln-1', label: 'CVE-2021-44228', type: 'VULNERABLE_COMPONENT', severity: 'CRITICAL', isExploitable: true, subtitle: '', metadata: {} },
            { id: 'vuln-2', label: 'CVE-2020-0001', type: 'VULNERABLE_COMPONENT', severity: 'MEDIUM', isExploitable: false, subtitle: '', metadata: {} },
            { id: 'secret-1', label: 'aws-key', type: 'SECRET', severity: 'HIGH', isExploitable: false, subtitle: '', metadata: {} }
        ],
        edges: [],
        attackPaths: [{ id: 'path-1', nodeIds: ['ingress-ext', 'ep-1', 'vuln-1', 'secret-1'], severity: 'CRITICAL', isExploitable: true, description: '' }]
    };

    beforeEach(async () => {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [AttackPaths],
            providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        fixture = TestBed.createComponent(AttackPaths);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();

        http.expectOne((call) => call.url === '/api/v1/attack-paths/overview').flush([GRAPH]);
        http.expectOne((call) => call.url === '/api/v1/repositories').flush(REPOSITORIES);
        // Selecting the first repository is what triggers the graph load.
        http.expectOne((call) => call.url === '/api/v1/attack-paths/repositories/7').flush(GRAPH);
    }, 20_000);

    it('lays the chain out in columns, ingress through to the sink', () => {
        const component = fixture.componentInstance;

        expect(component.ingressNodes().map((n) => n.id)).toEqual(['ingress-ext']);
        expect(component.endpointNodes()).toHaveLength(2);
        expect(component.vulnNodes()).toHaveLength(2);
        expect(component.sinkNodes().map((n) => n.id)).toEqual(['secret-1']);
    });

    it('narrows endpoints and vulnerabilities to the exploitable ones when asked', () => {
        const component = fixture.componentInstance;
        component.filterCriticalOnly.set(true);

        expect(component.endpointNodes().map((n) => n.id)).toEqual(['ep-1']);
        expect(component.vulnNodes().map((n) => n.id)).toEqual(['vuln-1']);
    });

    it('keeps the sink visible under the filter, because a reachable secret is the point', () => {
        // **The asymmetry is deliberate and this pins it.** `isExploitable` on a secret says
        // whether that node is itself an entry, not whether anything reaches it — the secret in
        // this fixture is the end of an exploitable path while carrying `false`. Filtering sinks
        // on that flag would hide the thing the screen exists to show, and the graph would read
        // as a chain that stops at the vulnerability.
        const component = fixture.componentInstance;
        component.filterCriticalOnly.set(true);

        expect(component.sinkNodes().map((n) => n.id)).toEqual(['secret-1']);
    });

    it('highlights exactly the nodes of the selected path', () => {
        const component = fixture.componentInstance;
        expect(component.highlightedNodeIds().size).toBe(0);

        component.selectedPath.set(GRAPH.attackPaths[0] as never);
        expect([...component.highlightedNodeIds()].sort())
            .toEqual(['ep-1', 'ingress-ext', 'secret-1', 'vuln-1']);
    });

    it('reports a failed graph load instead of leaving the last graph on screen', () => {
        const component = fixture.componentInstance;

        component.onRepoChange(9);
        http.expectOne((call) => call.url === '/api/v1/attack-paths/repositories/9')
            .flush('boom', { status: 500, statusText: 'Server Error' });

        // A screen that keeps repository 7's chain while the selector says 9 is worse than an
        // error: it attributes one target's exposure to another.
        expect(component.error()).not.toBeNull();
        expect(component.loading()).toBe(false);
    });
});
