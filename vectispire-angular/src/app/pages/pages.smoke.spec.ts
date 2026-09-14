import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { Type } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideRouter, Routes } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';

import { appRoutes } from '@/app.routes';
import { ScanDetailPage } from './scans/scan-detail';

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
            providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])]
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
        if (url.endsWith('/settings')) return { settings: [] };
        if (url.endsWith('/ticket-token')) return { configured: false };
        if (url.endsWith('/webhook-secret')) return { configured: false };
        if (url.endsWith('/issues')) return { items: [], total: 0, limit: 50, offset: 0 };
        if (url.endsWith('/audit-log')) return { items: [], total: 0, limit: 50, offset: 0 };
        if (url.endsWith('/security/overview')) {
            return { generatedAt: '2026-08-21T09:00:00Z', targets: [], failing: [], passing: 0, failingCount: 0 };
        }
        if (url.endsWith('/quality/overview')) {
            return { openCount: 0, ruleCount: 0, topRules: [], topFiles: [], topRepositories: [] };
        }
        // Before `/dashboard`, which this URL does not end with: an empty series is a fresh
        // install, and the mean is absent rather than zero on purpose.
        if (url.includes('/dashboard/analytics')) return { mttrBySeverity: { CRITICAL: null, HIGH: null, MEDIUM: null, LOW: null }, resolvedThisMonth: 0, slaComplianceRate: 100 };
        if (url.includes('/dashboard/trends')) return { points: [], mean_days_to_resolve: null, resolved_in_window: 0 };
        if (url.endsWith('/dashboard')) {
            return {
                posture: { failingCount: 0, totalCount: 0, kevCount: 0, neverScannedCount: 0, lastScanFailedCount: 0 },
                backlogBySeverity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
                qualityTotal: 0,
                failing: [],
                recentScans: []
            };
        }
        if (url.endsWith('/rule-sets')) return { ruleSets: [] };
        // Le registre porte ses compteurs à côté de ses lignes : rendu à vide, c'est un objet
        // dont `entries` est une liste, jamais une liste nue.
        if (url.includes('/exceptions')) {
            return { entries: [], granted: 0, awaiting_approval: 0, lapsed: 0, never_reviewed: 0 };
        }
        // ApiKeysController.Targets: two named lists, not a collection.
        if (url.endsWith('/api-keys/targets')) return { repositories: [], containers: [] };
        if (url.endsWith('/attack-surface')) {
            return {
                totalEndpoints: 0,
                publicEndpoints: 0,
                internalEndpoints: 0,
                unauthenticatedEndpoints: 0,
                shadowEndpoints: 0,
                sensitiveUnprotectedEndpoints: 0,
                frameworks: [],
                highRiskEndpoints: []
            };
        }
        if (url.includes('/apis')) {
            return {
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
            };
        }
        if (url.includes('/audit-log/operation-types')) return [];

        // **Quatre formes que ce fichier ne connaissait pas**, parce qu'il ne montait pas les
        // écrans qui les demandent. Elles sont arrivées avec la dérivation depuis les routes :
        // aucune n'est un défaut d'écran — le serveur envoie toujours ces cartes, jamais nulles —
        // mais un gabarit qui lit `sommaire.repartition['X']` sur le tableau vide que ce
        // fabricant rendait par défaut lève avant d'afficher quoi que ce soit.
        if (url.endsWith('/epss/priorities')) {
            return {
                totalVulnerabilities: 0, activeKevCount: 0, highEpssCount: 0,
                reachableEpssCount: 0, averageFleetEpss: 0, topPriorities: [],
                breakdownByTier: {}
            };
        }
        if (url.endsWith('/gate/policies')) {
            const builtIn = {
                kind: 'built_in', target_id: null, target_name: null, version: 0,
                fail_on_severity: null, fail_on_kev: false, fixable_only: false,
                include_triaged: false, include_ai_review: false, note: null,
                created_by: null, created_at: null
            };
            return { policies: [], built_in: builtIn };
        }
        if (url.endsWith('/compliance/summary')) {
            return {
                evaluations: [],
                mttr: { mttrBySeverityDays: {}, overallMttrDays: null, resolvedCount: 0 },
                overdueCount: 0, dueSoonCount: 0,
                totalMonitoredTargets: 0, passingGateTargets: 0, targets: []
            };
        }
        if (url.endsWith('/licenses/summary')) {
            return { totalDependencies: 0, uniqueLicenses: 0, nonCompliantCount: 0, breakdownByRisk: {} };
        }
        if (url.endsWith('/licenses/policy')) {
            return { disallowedCategories: [], explicitlyAllowedLicenses: [], explicitlyDisallowedLicenses: [] };
        }
        if (url.endsWith('/licenses/matrix')) return { entries: [] };
        if (url.endsWith('/remediation/debt')) {
            return {
                totalOpenIssues: 0, criticalIssues: 0, highIssues: 0, mediumIssues: 0, lowIssues: 0,
                totalEstimatedHours: 0, totalEstimatedPersonDays: 0, vulnerabilitiesDebtHours: 0,
                secretsDebtHours: 0, sastDebtHours: 0, iacDebtHours: 0, licenseDebtHours: 0,
                eolDebtHours: 0, topHighImpactFixes: []
            };
        }

        // Everything else in this application is a collection.
        return [];
    }

    /**
     * Les écrans montés à part, avec la raison — et la raison est vérifiée.
     *
     * <p>Chacun a besoin de plus qu'un `createComponent` : une entrée de route obligatoire, ou
     * une réponse serveur d'une forme que ce fichier ne sait pas fabriquer à vide. Les exempter
     * est légitime ; les exempter en silence ne l'est pas, et c'est ce que faisait la liste
     * écrite à la main — elle ne disait pas ce qu'elle omettait.
     */
    const MOUNTED_APART: Record<string, string> = {
        'scans/:id': "prend son identifiant de la route : une entrée obligatoire non posée lève NG0950 avant le gabarit",
        'login': "hors du layout, et son propre fichier de spec l'éprouve",
        'change-password': "hors du layout, éprouvé par la suite navigateur",
        'error': "une page statique sans appel serveur",
        'issues/:id': "prend son identifiant de la route, comme le détail de scan"
    };

    /**
     * Tous les écrans que la table des routes déclare, et non ceux dont quelqu'un s'est souvenu.
     *
     * <p><b>Ce fichier s'appelle « every screen » et en montait dix-sept sur trente et un.</b>
     * `blast-radius`, `epss`, `notifications`, `forbidden` et `notfound` n'étaient montés par
     * aucun test, nulle part — dont l'explorateur de rayon d'impact, l'écran le plus lourd du
     * produit. Une liste recopiée à la main couvre ce dont on s'est souvenu le jour où on l'a
     * écrite ; c'est un garde-fou qui a l'air d'en être un, exactement ce que
     * `ReadCostSweepTest` dit de la table des routes un étage plus bas.
     *
     * <p>Un écran ajouté demain est donc monté demain, sans que personne y pense — et un écran
     * qu'on veut exempter doit être nommé dans `MOUNTED_APART`, avec sa raison.
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

    it('exempte des écrans qui existent, et seulement ceux-là', () => {
        // Une exemption périmée est pire qu'aucune : elle nomme un écran disparu et laisse croire
        // que le reste est couvert. Celle-ci tombe le jour où le chemin change.
        const routed = new Set(ALL.map((screen) => screen.path));
        for (const path of Object.keys(MOUNTED_APART)) {
            expect(routed.has(path), `${path} n'est plus une route : l'exemption est périmée`).toBe(true);
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
            request.flush({
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
                targetName: 'Arm Libs Spring',
                subPath: null,
                projectType: 'maven',
                projectVersion: '1.17.6',
                hasSbom: false,
                findings: [],
                findingsTotal: 0,
                findingsTruncated: false
            });
        }
        fixture.detectChanges();

        expect(fixture.nativeElement.textContent).toBeDefined();
        http.verify();
    });
});
