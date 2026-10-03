import { provideHttpClient, withXhr } from '@angular/common/http';
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
        scannedAt: '2026-08-21T05:03:00Z',
        source: 'scanner',
        scannerVersion: null
    });

    beforeEach(async () => {
        await TestBed.configureTestingModule({
            imports: [Inventory],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting()]
        }).compileComponents();

        TestBed.inject(I18nService).translations.set({
            inventory: {
                source_build: 'build',
                source_build_hint: "Listed by the build's SBOM only.",
                source_both_hint: "Version stated by the build's SBOM; the scanner read {{version}}.",
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
        request.flush(asSchema('Results', { occurrences: [], total: 0, truncated: false }));
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

    it("says which versions the build's SBOM stated, and what the scanner read instead", () => {
        search('spring', '', {
            occurrences: [
                {
                    ...OCCURRENCE,
                    component: 'spring-core',
                    componentVersion: '6.1.14',
                    source: 'both',
                    scannerVersion: 'UNKNOWN'
                },
                { ...OCCURRENCE, component: 'spring-jcl', componentVersion: '6.1.14', source: 'build', scanId: 35 },
                { ...OCCURRENCE, component: 'left-pad', componentVersion: '1.3.0', scanId: 36 }
            ],
            total: 3,
            truncated: false
        });

        const rows = Array.from((fixture.nativeElement as HTMLElement).querySelectorAll<HTMLElement>('tbody tr'));
        const tagOf = (row: HTMLElement) => row.querySelector('p-tag[title]');
        // A version the build resolved is said to be the build's — a reviewer must not read the scanner's
        // UNKNOWN into it, nor take a transitive library for one found in the tree.
        expect(tagOf(rows[0])?.getAttribute('title')).toContain('the scanner read UNKNOWN');
        expect(tagOf(rows[1])?.getAttribute('title')).toContain("build's SBOM only");
        expect(tagOf(rows[2])).toBeNull();
    });

    it('does not search on an empty name', () => {
        fixture.componentInstance.name = '   ';
        fixture.componentInstance.search();
        http.expectNone((call) => call.url.startsWith('/api/v1/inventory/search'));
    });

    it('distinguishes "nothing catalogued" from "we do not use it"', () => {
        search('nothing', '', { occurrences: [], total: 0, truncated: false });

        const text = fixture.nativeElement.textContent;
        expect(text.includes('No scan has catalogued this component') || text.includes('inventory.no_results')).toBe(
            true
        );
    });

    /** A scan as the history returns it: newest first, and what the pickers read. */
    const scan = (id: number, when: string) => ({
        id,
        status: 'completed',
        branch: 'main',
        targetKind: 'REPOSITORY',
        targetName: 'helios-portal',
        createdAt: when,
        durationMs: 1200,
        findingsCount: 7,
        newIssuesCount: 0,
        resolvedIssuesCount: 0,
        error: null,
        claimedBy: null,
        attempts: 1,
        notBefore: null,
        targetId: 5
    });

    it("offers the target's own scans, and preselects the last two", () => {
        // **The question as it is asked.** This screen took two internal identifiers — `ex: 10`,
        // `ex: 12` — that no screen displays prominently, for a question that is almost always
        // "what changed since last time". The server had listed a target's scans all along.
        const page = fixture.componentInstance;
        page.diffTarget = 'repo:5';
        page.onTargetChosen();

        const call = http.expectOne((request) => request.url.includes('/api/v1/scans'));
        expect(call.request.params.get('repo_id')).toBe('5');
        expect(call.request.params.get('container_id')).toBeNull();
        call.flush([scan(34, '2026-09-18T09:00:00Z'), scan(33, '2026-09-17T09:00:00Z')]);
        fixture.detectChanges();

        // Newest into "to", the one before it into "from": the common case is answered by opening
        // the screen rather than by a second click.
        expect(page.toScanId).toBe(34);
        expect(page.fromScanId).toBe(33);
        expect(page.diffError()).toBeNull();
    });

    it("carries the target's kind, an image not being listed like a repository", () => {
        const page = fixture.componentInstance;
        page.diffTarget = 'container:3';
        page.onTargetChosen();

        const call = http.expectOne((request) => request.url.includes('/api/v1/scans'));
        expect(call.request.params.get('container_id')).toBe('3');
        expect(call.request.params.get('repo_id')).toBeNull();
        call.flush([]);
    });

    it('tells "nothing to compare" apart from "the listing failed"', () => {
        // A target scanned once has no pair. Saying so is a different sentence from a server that
        // is down, and only one of the two is about this repository.
        const page = fixture.componentInstance;
        page.diffTarget = 'repo:5';
        page.onTargetChosen();
        http.expectOne((request) => request.url.includes('/api/v1/scans')).flush([scan(34, '2026-09-18T09:00:00Z')]);
        fixture.detectChanges();

        expect(page.diffError()).toContain('nothing to compare yet');
        expect(page.fromScanId).toBeNull();

        page.onTargetChosen();
        http.expectOne((request) => request.url.includes('/api/v1/scans')).flush(null, {
            status: 500,
            statusText: 'Server Error'
        });
        fixture.detectChanges();

        expect(page.diffError()).toContain('could not be computed');
    });

    it('asks for nothing until a target is chosen', () => {
        fixture.componentInstance.diffTarget = '';
        fixture.componentInstance.onTargetChosen();

        http.expectNone((request) => request.url.includes('/api/v1/scans'));
    });

    it('reads a scan as a date a human recognises, with its number kept at the end', () => {
        // The identifier stays because it is what the API takes and what a support conversation
        // quotes; it is simply no longer the only thing on offer.
        const label = fixture.componentInstance.scanLabel(scan(34, '2026-09-18T09:00:00Z'));

        expect(label).toContain('#34');
        expect(label).toContain('main');
    });

    it("names each change in the reader's language, not in the French it was first typed in", () => {
        // The tags read `AJOUTÉ`, `SUPPRIMÉ`, `INCHANGÉ` as static attributes, to every reader: no
        // language preference reached them, and no check read a `value=`.
        TestBed.inject(I18nService).translations.set({
            inventory: {
                delta_added: 'ADDED',
                delta_removed: 'REMOVED',
                delta_version: 'VERSION',
                delta_license: 'LICENSE',
                delta_unchanged: 'UNCHANGED'
            }
        });
        const page = fixture.componentInstance;
        page.activeTab.set('diff');
        page.diffReport.set(
            asSchema('SbomDiffReport', {
                fromScanId: 33,
                toScanId: 34,
                fromVersion: null,
                toVersion: null,
                cveDeltas: [],
                addedCount: 1,
                removedCount: 1,
                versionChangedCount: 1,
                licenseChangedCount: 1,
                resolvedCveCount: 0,
                introducedCveCount: 0,
                componentDeltas: (['ADDED', 'REMOVED', 'VERSION_CHANGED', 'LICENSE_CHANGED', 'UNCHANGED'] as const).map(
                    (changeType, index) => ({
                        name: `lib-${index}`,
                        changeType,
                        type: null,
                        purl: null,
                        oldVersion: null,
                        newVersion: null,
                        oldLicense: null,
                        newLicense: null
                    })
                )
            })
        );
        fixture.detectChanges();

        const tags = [...(fixture.nativeElement as HTMLElement).querySelectorAll('p-tag')].map((tag) =>
            tag.textContent.trim()
        );
        expect(tags).toEqual(['ADDED', 'REMOVED', 'VERSION', 'LICENSE', 'UNCHANGED']);
    });
});
