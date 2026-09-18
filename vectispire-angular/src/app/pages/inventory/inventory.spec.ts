import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { beforeEach, describe, expect, it } from 'vitest';
import { Inventory } from './inventory';
import { I18nService } from '@/app/core/i18n/i18n.service';
import { asSchema } from '@/app/core/testing/contract';

/**
 * The component search.
 *
 * <p>The screen exists to answer "do we ship this library, and in which release of ours". The two
 * versions on a row — the library's and the project's — are the whole point, and confusing them
 * is the one mistake that makes the answer useless. That is what this suite guards.
 */
describe('the component search', () => {
    let fixture: ComponentFixture<Inventory>;
    let http: HttpTestingController;

    const OCCURRENCE = asSchema('Occurrence', {
            component: 'log4j-core',
            componentVersion: '2.14.1',
            purl: 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1',
            type: 'java-archive',
            direct: true,
            targetKind: 'repository',
            targetId: 5,
            targetName: 'Arm Libs Spring',
            branch: 'master',
            projectVersion: '1.17.6',
            scanId: 34,
            scannedAt: '2026-08-21T05:03:00Z'
    });

    beforeEach(async () => {
        await TestBed.configureTestingModule({
            imports: [Inventory],
            providers: [provideHttpClient(), provideHttpClientTesting()]
        }).compileComponents();

        TestBed.inject(I18nService).translations.set({
            inventory: {
                diff_needs_two_scans: 'This target has a single scan: there is nothing to compare yet.',
                diff_needs_two_ids: 'Name the two scans to compare.',
                diff_failed: 'The difference could not be computed.'
            }
        });

        fixture = TestBed.createComponent(Inventory);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();

        // The two target lists, asked for by the constructor for the picker.
        for (const request of http.match((r) => r.url.includes('/repositories') || r.url.includes('/containers'))) {
            request.flush([]);
        }
    });

    function search(name: string, version: string, results: Record<string, unknown>): void {
        fixture.componentInstance.name = name;
        fixture.componentInstance.version = version;
        fixture.componentInstance.search();
        // The service builds its own query string, so the URL carries it.
        http.expectOne((request) => request.url.startsWith('/api/v1/inventory/search')).flush(results);
        fixture.detectChanges();
    }

    it('shows the library version and our release side by side', () => {
        search('log4j', '', { occurrences: [OCCURRENCE], total: 1, truncated: false });

        const text = fixture.nativeElement.textContent as string;
        expect(text).toContain('log4j-core');
        expect(text).toContain('2.14.1');
        // The half that makes the answer actionable rather than merely true.
        expect(text).toContain('1.17.6');
        expect(text).toContain('Arm Libs Spring');
    });

    it('passes the exact version to the server rather than filtering loosely here', () => {
        fixture.componentInstance.name = 'log4j';
        fixture.componentInstance.version = '2.14.1';
        fixture.componentInstance.search();

        const request = http.expectOne((call) => call.url.startsWith('/api/v1/inventory/search'));
        // A prefix match would report a release as affected when it is not — the kind of wrong
        // answer that gets acted on, because it is plausible.
        expect(request.request.urlWithParams).toContain('version=2.14.1');
        request.flush({ occurrences: [], total: 0, truncated: false });
    });

    it('says a capped list is capped', () => {
        search('log4j', '', { occurrences: [OCCURRENCE], total: 500, truncated: true });

        // A capped list read as complete is a wrong answer to "is that all of them".
        const text = fixture.nativeElement.textContent;
        expect(text.includes('narrow the search by version') || text.includes('inventory.truncated_warn')).toBe(true);
    });

    it('does not present an unknown origin as transitive', () => {
        search('mystery', '', {
            occurrences: [{ ...OCCURRENCE, component: 'mystery-lib', direct: null }],
            total: 1,
            truncated: false
        });

        const text = fixture.nativeElement.textContent as string;
        // Several ecosystems ship no dependency graph; "transitive" there would state something
        // nothing established.
        expect(text).toContain('unknown');
        expect(text).not.toContain('transitive');
    });

    it('does not search on an empty name', () => {
        fixture.componentInstance.name = '   ';
        fixture.componentInstance.search();
        http.expectNone((call) => call.url.startsWith('/api/v1/inventory/search'));
    });

    it('distinguishes "nothing catalogued" from "we do not use it"', () => {
        search('nothing', '', { occurrences: [], total: 0, truncated: false });

        const text = fixture.nativeElement.textContent;
        expect(text.includes('No scan has catalogued this component') || text.includes('inventory.no_results')).toBe(true);
    });

    it('asks for the latest pair of scans, with no number to type', () => {
        // **The question as it is asked.** It took typing two internal identifiers no screen
        // displays prominently, when the server could already answer "what changed on this target
        // since last time".
        const page = fixture.componentInstance;
        page.diffTarget = 'repo:5';
        page.runLatestDiff();

        const call = http.expectOne((request) => request.url.includes('/sbom/diff/latest'));
        expect(call.request.params.get('repoId')).toBe('5');
        expect(call.request.params.get('containerId')).toBeNull();
        call.flush({ fromScanId: 33, toScanId: 34, addedCount: 2, removedCount: 0, componentDeltas: [], cveDeltas: [] });
        fixture.detectChanges();

        expect(page.diffReport()?.toScanId).toBe(34);
    });

    it('carries the target\'s kind, an image not being compared like a repository', () => {
        const page = fixture.componentInstance;
        page.diffTarget = 'container:3';
        page.runLatestDiff();

        const call = http.expectOne((request) => request.url.includes('/sbom/diff/latest'));
        expect(call.request.params.get('containerId')).toBe('3');
        expect(call.request.params.get('repoId')).toBeNull();
        call.flush({ fromScanId: 1, toScanId: 2, addedCount: 0, componentDeltas: [], cveDeltas: [] });
    });

    it('tells "nothing to compare" apart from "the calculation failed"', () => {
        // A target scanned only once has no pair. Returning the same error as a server that is down
        // would send somebody looking for a failure that does not exist.
        const page = fixture.componentInstance;
        page.diffTarget = 'repo:5';
        page.runLatestDiff();
        http.expectOne((request) => request.url.includes('/sbom/diff/latest'))
            .flush(null, { status: 404, statusText: 'Not Found' });
        fixture.detectChanges();

        expect(page.diffError()).toContain('nothing to compare yet');

        page.runLatestDiff();
        http.expectOne((request) => request.url.includes('/sbom/diff/latest'))
            .flush(null, { status: 500, statusText: 'Server Error' });
        fixture.detectChanges();

        expect(page.diffError()).toContain('could not be computed');
    });

    it("ne demande rien tant qu'aucune cible n'est choisie", () => {
        fixture.componentInstance.runLatestDiff();

        http.expectNone((request) => request.url.includes('/sbom/diff/latest'));
    });
});
