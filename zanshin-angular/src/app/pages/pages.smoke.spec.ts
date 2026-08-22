import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { Type } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';

import { Agents } from './agents/agents';
import { ApiKeys } from './api-keys/api-keys';
import { AuditLog } from './audit-log/audit-log';
import { Containers } from './containers/containers';
import { Dashboard } from './dashboard/dashboard';
import { Quality } from './quality/quality';
import { Repositories } from './repositories/repositories';
import { RuleSets } from './rule-sets/rule-sets';
import { ScanDetailPage } from './scans/scan-detail';
import { Security } from './security/security';
import { SshKeys } from './ssh-keys/ssh-keys';
import { Teams } from './teams/teams';
import { Users } from './users/users';

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
        if (url.endsWith('/issues')) return { items: [], total: 0, limit: 50, offset: 0 };
        if (url.endsWith('/audit-log')) return { items: [], total: 0, limit: 50, offset: 0 };
        if (url.endsWith('/security/overview')) {
            return { generatedAt: '2026-08-21T09:00:00Z', targets: [], failing: [], passing: 0, failingCount: 0 };
        }
        if (url.endsWith('/quality/overview')) {
            return { openCount: 0, ruleCount: 0, topRules: [], topFiles: [], topRepositories: [] };
        }
        if (url.endsWith('/dashboard')) {
            return {
                posture: { failingCount: 0, totalCount: 0, kevCount: 0, neverScannedCount: 0, lastScanFailedCount: 0 },
                backlogBySeverity: {},
                qualityTotal: 0,
                failing: [],
                recentScans: []
            };
        }
        if (url.endsWith('/rule-sets')) return { ruleSets: [] };
        // ApiKeysController.Targets: two named lists, not a collection.
        if (url.endsWith('/api-keys/targets')) return { repositories: [], containers: [] };
        if (url.includes('/audit-log/operation-types')) return [];
        // Everything else in this application is a collection.
        return [];
    }

    const SCREENS: [string, Type<unknown>][] = [
        ['Dashboard', Dashboard],
        ['Repositories', Repositories],
        ['Containers', Containers],
        ['Security', Security],
        ['Quality', Quality],
        ['Agents', Agents],
        ['API keys', ApiKeys],
        ['SSH keys', SshKeys],
        ['Users', Users],
        ['Teams', Teams],
        ['Audit log', AuditLog],
        ['Semgrep rules', RuleSets]
    ];

    it.each(SCREENS)('%s renders against an empty server', (_name, component) => {
        const fixture = TestBed.createComponent(component);
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
