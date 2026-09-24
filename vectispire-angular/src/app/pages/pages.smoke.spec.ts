import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { Type } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideRouter, Routes } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';

import { appRoutes } from '@/app.routes';
import { ScanDetailPage } from './scans/scan-detail';
import { asSchema } from '@/app/core/testing/contract';

/**
 * Every screen mounts, renders, and survives an empty server.
 *
 * <h2>Why a shallow suite is worth writing</h2>
 *
 * <p>A template is not type-checked the way the class around it is, and the failures it produces
 * are invisible until somebody opens the page. This session shipped three of them — a button
 * gated on a condition that could never be true, a page that returned 500, four downloads that
 * saved zero bytes — with a green build each time.
 *
 * <p>This asserts almost nothing about behaviour on purpose. It asserts the one thing no other
 * check covers: that the component can be created, that its template binds against the data the
 * server really sends, and that an <b>empty</b> answer — the state of every screen on a fresh
 * install — does not throw. The screens whose behaviour matters have suites of their own beside
 * this one.
 */
describe('every screen', () => {
    let http: HttpTestingController;

    beforeEach(async () => {
        await TestBed.configureTestingModule({
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();
        http = TestBed.inject(HttpTestingController);
    });

    /**
     * An empty answer shaped like the route's.
     *
     * <p>A list route answered with an object, or the reverse, throws in the template — which
     * would be a failure of this helper rather than of the screen. The shape is read from the
     * URL because that is what the server's own contract keys on.
     */
    function emptyFor(url: string): Record<string, unknown> | unknown[] {
        if (url.endsWith('/settings')) return asSchema('Catalog', { settings: [] });
        // Two routes answering an anonymous shape: the document publishes no schema for either, so
        // there is nothing to anchor them to. Said rather than hidden.
        if (url.endsWith('/ticket-token')) return { configured: false };
        if (url.endsWith('/webhook-secret')) return { configured: false };
        if (url.endsWith('/issues')) return asSchema('IssuePage', { items: [], total: 0, limit: 50, offset: 0 });
        if (url.endsWith('/audit-log/operation-types')) return [];
        if (url.endsWith('/audit-log')) return asSchema('AuditLogPage', { items: [], total: 0, limit: 50, offset: 0 });
        if (url.endsWith('/security/overview')) {
            return asSchema('SecurityOverviewView', {
                targets: [], failingCount: 0, totalCount: 0, kevCount: 0,
                neverScannedCount: 0, lastScanFailedCount: 0
            });
        }
        if (url.endsWith('/quality/overview')) {
            return asSchema('QualityOverview', {
                openCount: 0, ruleCount: 0, fileCount: 0, topRules: [], topFiles: [], topTargets: []
            });
        }
        // **`/dashboard/analytics` matched no route.** The route is `/dashboard/posture-analytics`;
        // this pattern never reached it, and the request fell through to the empty array returned
        // by default — an array where the screen expects an object. A dead branch in a response
        // factory never throws: it simply returns something else.
        if (url.includes('/dashboard/posture-analytics')) {
            return asSchema('PostureTrendAnalytics', {
                windowDays: 30,
                overallMttrDays: null,
                mttrBySeverity: {},
                totalOpenedInWindow: 0,
                totalResolvedInWindow: 0,
                netResolutionRatePercentage: 0,
                dailySeries: [],
                targetScoreboard: []
            });
        }
        if (url.includes('/dashboard/trends')) {
            return asSchema('Trends', { points: [], mean_days_to_resolve: null, resolved_in_window: 0 });
        }
        if (url.endsWith('/dashboard')) {
            return asSchema('DashboardOverview', {
                posture: {
                    failingCount: 0, totalCount: 0, kevCount: 0,
                    neverScannedCount: 0, lastScanFailedCount: 0, overdueCount: 0
                },
                backlogBySeverity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
                qualityTotal: 0,
                failing: [],
                recentScans: []
            });
        }
        // Coverage is a verdict, not a collection: `COVERED` silences the banner, which is the
        // state of an empty server as much as of a well-configured one.
        if (url.endsWith('/rule-sets/coverage')) {
            return asSchema('Assessment', {
                state: 'COVERED', languagesWithRules: [], ecosystemsInEstate: [], uncovered: [], ruleFiles: 0
            });
        }
        if (url.endsWith('/rule-sets')) return asSchema('RuleSetListing', { ruleSets: [] });
        // The statement is a list of documents, one per framework: empty, it is an array.
        if (url.endsWith('/compliance/soa')) return [];
        // One series per framework: returned empty, it is an array, never an object.
        if (url.endsWith('/compliance/history')) return [];
        // The grid is one verdict per category: returned empty, it is an object of ten rows, never
        // a bare list.
        if (url.endsWith('/owasp/coverage')) {
            return asSchema('DeclaredGrid', { lines: [], covered: 0, withFindings: 0, unmeasured: 0 });
        }
        if (url.endsWith('/compliance/scope')) {
            return asSchema('ScopeView', {
                statement: '',
                coverage: { declaredAssets: 0, inScope: 0, scannedRecently: 0, stale: 0, neverScanned: 0 },
                targets: []
            });
        }
        if (url.includes('/remediation/distribution')) {
            return asSchema('RemediationDistributionView', {
                windowDays: 90, bySeverity: [], oldestOpenDays: null, oldestOpenSeverity: null
            });
        }
        if (url.includes('/gate/verdicts')) {
            return asSchema('VerdictRegister', { verdicts: [], passed: 0, refused: 0 });
        }
        if (url.includes('/exceptions')) {
            return asSchema('Register', {
                entries: [], granted: 0, awaiting_approval: 0, lapsed: 0, never_reviewed: 0
            });
        }
        // ApiKeysController.Targets: two named lists, not a collection.
        if (url.endsWith('/api-keys/targets')) return asSchema('Targets', { repositories: [], containers: [] });
        if (url.endsWith('/attack-surface')) {
            return asSchema('GlobalAttackSurface', {
                totalEndpoints: 0,
                publicEndpoints: 0,
                internalEndpoints: 0,
                unauthenticatedEndpoints: 0,
                shadowEndpoints: 0,
                sensitiveUnprotectedEndpoints: 0,
                frameworks: [],
                highRiskEndpoints: []
            });
        }
        if (url.includes('/apis')) {
            return asSchema('RepositoryApisOverview', {
                repositoryId: 1,
                endpoints: [],
                contracts: [],
                summary: {
                    totalEndpoints: 0,
                    publicEndpoints: 0,
                    internalEndpoints: 0,
                    unauthenticatedEndpoints: 0,
                    shadowEndpoints: 0,
                    sensitiveUnprotectedEndpoints: 0
                }
            });
        }

        // **Four shapes this file did not know about**, because it did not mount the screens that
        // ask for them. They arrived with the derivation from the route table: none is a screen
        // defect — the server always sends these maps, never null — but a template reading
        // `summary.breakdown['X']` on the empty array this factory returned by default throws
        // before showing anything at all.
        if (url.endsWith('/epss/priorities')) {
            return asSchema('EpssFleetSummary', {
                totalVulnerabilities: 0, activeKevCount: 0, highEpssCount: 0,
                reachableEpssCount: 0, averageFleetEpss: 0, topPriorities: [],
                breakdownByTier: {}
            });
        }
        if (url.endsWith('/gate/policies')) {
            const builtIn = asSchema('GatePolicyView', {
                kind: 'built_in', target_id: null, target_name: null, version: 0,
                fail_on_severity: null, fail_on_kev: false, fixable_only: false,
                include_triaged: false, include_ai_review: false,
                fail_on_uncovered_languages: false, note: null,
                created_by: null, created_at: null
            });
            return asSchema('PoliciesResponse', { policies: [], built_in: builtIn });
        }
        if (url.endsWith('/compliance/summary')) {
            return asSchema('ComplianceSummary', {
                evaluations: [],
                mttr: { mttrBySeverityDays: {}, overallMttrDays: null, resolvedCount: 0 },
                overdueCount: 0, dueSoonCount: 0,
                totalMonitoredTargets: 0, passingGateTargets: 0,
                observedTargets: 0, freshTargets: 0, targets: []
            });
        }
        if (url.endsWith('/licenses/summary')) {
            return asSchema('LicenseSummary', {
                totalDependencies: 0, uniqueLicenses: 0, nonCompliantCount: 0, breakdownByRisk: {}
            });
        }
        if (url.endsWith('/licenses/policy')) {
            return asSchema('LicensePolicy', {
                disallowedCategories: [], explicitlyAllowedLicenses: [], explicitlyDisallowedLicenses: []
            });
        }
        // **The matrix is an array, and this factory returned `{ entries: [] }`.** The route
        // answers `CompatibilityCell[]`; an object in its place is precisely the case the comment
        // at the top of this function says it wants to avoid.
        if (url.endsWith('/licenses/matrix')) return [];
        if (url.endsWith('/remediation/debt')) {
            return asSchema('SecurityDebtReport', {
                totalOpenIssues: 0, criticalIssues: 0, highIssues: 0, mediumIssues: 0, lowIssues: 0,
                totalEstimatedHours: 0, totalEstimatedPersonDays: 0, vulnerabilitiesDebtHours: 0,
                secretsDebtHours: 0, sastDebtHours: 0, iacDebtHours: 0, licenseDebtHours: 0,
                eolDebtHours: 0, topHighImpactFixes: []
            });
        }

        // Everything else in this application is a collection.
        return [];
    }

    /**
     * The screens mounted apart, with the reason — and the reason is checked.
     *
     * <p>Each needs more than a `createComponent`: a mandatory route input, or a server response of
     * a shape this file cannot manufacture empty. Exempting them is legitimate; exempting them
     * silently is not, and that is what the hand-written list did — it did not say what it left
     * out.
     */
    const MOUNTED_APART: Record<string, string> = {
        'scans/:id': 'takes its id from the route: a required input left unset throws NG0950 before the template',
        'login': 'outside the layout, and its own spec file tests it',
        'change-password': 'outside the layout, tested by the browser suite',
        'error': 'a static page with no server call',
        'issues/:id': 'takes its id from the route, like the scan detail'
    };

    /**
     * Every screen the route table declares, and not the ones somebody remembered.
     *
     * <p><b>This file is called "every screen" and mounted seventeen out of thirty-one.</b>
     * `blast-radius`, `epss`, `notifications`, `forbidden` and `notfound` were mounted by no test,
     * anywhere — including the blast-radius explorer, the heaviest screen in the product. A list
     * copied by hand covers what was remembered on the day it was written; it is a guard rail that
     * looks like one, exactly what `ReadCostSweepTest` says of the route table one floor below.
     *
     * <p>A screen added tomorrow is therefore mounted tomorrow, without anybody thinking about it —
     * and a screen to be exempted must be named in `MOUNTED_APART`, with its reason.
     */
    function routedScreens(): { path: string; load: () => Promise<Type<unknown>> }[] {
        const found: { path: string; load: () => Promise<Type<unknown>> }[] = [];
        const walk = (routes: Routes, prefix: string) => {
            for (const route of routes) {
                const path = [prefix, route.path].filter((part) => part).join('/');
                if (route.loadComponent) {
                    found.push({ path, load: route.loadComponent as () => Promise<Type<unknown>> });
                }
                if (route.children) {
                    walk(route.children, path);
                }
            }
        };
        walk(appRoutes, '');
        return found;
    }

    const ALL = routedScreens();
    const SCREENS: [string, () => Promise<Type<unknown>>][] = ALL
        .filter((screen) => !(screen.path in MOUNTED_APART))
        .map((screen) => [screen.path, screen.load]);

    it('exempts screens that exist, and only those', () => {
        // A stale exemption is worse than none: it names a screen that is gone and suggests the
        // rest is covered. This one falls the day the path changes.
        const routed = new Set(ALL.map((screen) => screen.path));
        for (const path of Object.keys(MOUNTED_APART)) {
            expect(routed.has(path), `${path} is no longer a route: the exemption is stale`).toBe(true);
        }
        expect(SCREENS.length).toBeGreaterThan(20);
    });

    it.each(SCREENS)('%s renders against an empty server', async (_path, load) => {
        const fixture = TestBed.createComponent(await load());
        fixture.detectChanges();

        // Whatever the screen asked for, answered empty. A screen that throws on no data is a
        // screen that throws on a fresh install.
        for (const request of http.match(() => true)) {
            request.flush(emptyFor(request.request.url));
        }
        fixture.detectChanges();

        // The coverage banner lives inside the block that waits for the data, so it does not exist
        // yet at the pass above, and its request only arrives once the screen has rendered.
        for (const request of http.match(() => true)) {
            request.flush(emptyFor(request.request.url));
        }
        fixture.detectChanges();

        expect(fixture.nativeElement.textContent).toBeDefined();
        http.verify();
    });

    /**
     * The scan detail takes its id from the route, so it is mounted apart: a required input left
     * unset throws NG0950 before the template runs, which would say nothing about the screen.
     */
    it('Scan detail renders against an empty server', () => {
        const fixture = TestBed.createComponent(ScanDetailPage);
        fixture.componentRef.setInput('id', '34');
        fixture.detectChanges();

        for (const request of http.match(() => true)) {
            // The summary is nested under `scan`, as the route sends it. This fixture used to
            // spread it flat — the same belief the client type held — so the screen reading
            // `detail.id` found nothing here and nothing in production, and both agreed.
            request.flush(asSchema('ScanDetail', {
                scan: {
                    id: 34,
                    status: 'completed',
                    branch: 'master',
                    createdAt: '2026-08-21T05:03:00Z',
                    durationMs: 1000,
                    findingsCount: 0,
                    newIssuesCount: 0,
                    resolvedIssuesCount: 0,
                    error: null,
                    claimedBy: null,
                    attempts: 1,
                    targetKind: 'repository',
                    targetId: 5,
                    targetName: 'Arm Libs Spring'
                },
                subPath: null,
                projectType: 'maven',
                projectVersion: '1.17.6',
                hasSbom: false,
                findings: [],
                findingsTotal: 0,
                findingsTruncated: false
            }));
        }
        fixture.detectChanges();

        // Same reason as above: the coverage banner sits inside the block that waits for the
        // detail, so its request only exists once that has rendered.
        for (const request of http.match(() => true)) {
            request.flush(emptyFor(request.request.url));
        }
        fixture.detectChanges();

        expect(fixture.nativeElement.textContent).toBeDefined();
        http.verify();
    });
});
