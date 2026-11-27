import { TestBed } from '@angular/core/testing';
import { afterEach, describe, expect, it } from 'vitest';
import type { ScanDetail, ScanSummary } from '@/app/core/api.models';
import { asSchema, asSchemaList } from '@/app/core/testing/contract';
import { repositorySummary } from '@/app/core/testing/targets.fixtures';
import { SBOM_LOOKBACK } from './latest-sbom';
import { RepositoryList } from './repository-list';
import { SbomDialog } from './sbom-dialog';
import { mountOnRepositories, namedButton, textOf } from './repositories-page.testing';

/** A scan of repository 5 as `GET /api/v1/scans` lists it. */
function scan(id: number, status: string, createdAt = '2026-11-20T08:30:00Z'): ScanSummary {
    return asSchema('ScanSummary', {
        id,
        status,
        branch: 'main',
        targetKind: 'repository',
        targetName: 'repository-5',
        targetId: 5,
        createdAt,
        durationMs: null,
        error: null,
        claimedBy: null,
        notBefore: null,
        attempts: 1,
        findingsCount: 0,
        newIssuesCount: 0,
        resolvedIssuesCount: 0
    });
}

function detail(summary: ScanSummary, hasSbom: boolean): ScanDetail {
    return asSchema('ScanDetail', {
        scan: summary,
        subPath: null,
        projectType: null,
        projectVersion: null,
        hasSbom,
        findingsTotal: 0,
        findingsTruncated: false,
        findings: [],
        plugins: [],
        examinedTypes: null
    });
}

/**
 * The latest SBOM of a repository, from its card: the scan it comes from named before anything is
 * offered, an older scan said to be older, and nothing offered — with the reason — when there is none.
 */
describe("a repository's latest SBOM", () => {
    const originalClick = HTMLAnchorElement.prototype.click;
    const originalCreate = URL.createObjectURL.bind(URL);

    afterEach(() => {
        HTMLAnchorElement.prototype.click = originalClick;
        URL.createObjectURL = originalCreate;
        TestBed.resetTestingModule();
    });

    const repository = repositorySummary(5);

    function open() {
        const mounted = mountOnRepositories(SbomDialog, { repositories: [repository] });
        mounted.page.openSbom(repository);
        const list = mounted.http.expectOne((call) => call.url === '/api/v1/scans');
        expect(list.request.params.get('repo_id')).toBe('5');
        return { ...mounted, list };
    }

    const downloadButton = () => namedButton(document, 'Download SBOM (Syft JSON)');
    const cycloneDxButton = () => namedButton(document, 'CycloneDX with VEX');
    const source = () => textOf(document, '[data-testid="sbom-source"]');

    /** Records what the browser was asked to save, instead of letting happy-dom navigate. */
    function captureSaves(): string[] {
        const saved: string[] = [];
        URL.createObjectURL = () => 'blob:test';
        HTMLAnchorElement.prototype.click = function click(this: HTMLAnchorElement) {
            saved.push(this.download);
        };
        return saved;
    }

    it('takes the newest completed scan, not a newer one still running, and saves its SBOM', () => {
        const { fixture, http, list } = open();
        list.flush(asSchemaList('ScanSummary', [scan(12, 'scanning'), scan(11, 'completed'), scan(9, 'completed')]));
        http.expectOne('/api/v1/scans/11').flush(detail(scan(11, 'completed'), true));
        fixture.detectChanges();

        expect(source()).toContain('From scan #11');
        expect(source()).toContain('20/11/2026');
        expect(source()).not.toContain('older scan');
        expect(downloadButton().disabled).toBe(false);

        const saved = captureSaves();
        downloadButton().click();
        http.expectOne('/api/v1/scans/11/sbom').flush(new Blob(['{}']));
        cycloneDxButton().click();
        http.expectOne('/api/v1/cyclonedx/scans/11/cyclonedx-vex.json').flush(new Blob(['{}']));
        expect(saved).toEqual(['vectispire-scan-11.sbom.json', 'vectispire-scan-11.cyclonedx-vex.json']);
    });

    it('says the documents come from an older scan when the newest completed one has no SBOM', () => {
        const { fixture, http, list } = open();
        list.flush(asSchemaList('ScanSummary', [scan(11, 'completed'), scan(9, 'completed')]));
        http.expectOne('/api/v1/scans/11').flush(detail(scan(11, 'completed'), false));
        http.expectOne('/api/v1/scans/9').flush(detail(scan(9, 'completed', '2026-11-01T08:30:00Z'), true));
        fixture.detectChanges();

        expect(source()).toContain('From scan #9');
        expect(source()).toContain('The newest completed scan, #11, carries no SBOM');
        expect(downloadButton().disabled).toBe(false);
    });

    it('offers nothing, and says why, for a repository with no completed scan', () => {
        const { fixture, http, list } = open();
        list.flush(asSchemaList('ScanSummary', [scan(12, 'failed'), scan(10, 'pending')]));
        // No detail is read: no completed scan is a candidate.
        http.expectNone((call) => call.url.startsWith('/api/v1/scans/'));
        fixture.detectChanges();

        expect(source()).toContain('no completed scan among its latest 50');
        expect(downloadButton().disabled).toBe(true);
        expect(cycloneDxButton().disabled).toBe(true);
    });

    it('stops after the newest completed scans and says none of them has an SBOM', () => {
        const { fixture, http, list } = open();
        const completed = Array.from({ length: SBOM_LOOKBACK + 2 }, (_, i) => scan(100 - i, 'completed'));
        list.flush(asSchemaList('ScanSummary', completed));
        for (const candidate of completed.slice(0, SBOM_LOOKBACK)) {
            http.expectOne(`/api/v1/scans/${candidate.id}`).flush(detail(candidate, false));
        }
        http.expectNone((call) => call.url.startsWith('/api/v1/scans/'));
        fixture.detectChanges();

        expect(source()).toContain(`None of the ${SBOM_LOOKBACK} newest completed scans`);
        expect(downloadButton().disabled).toBe(true);
    });

    it("shows the server's reason when the scans cannot be read, and offers nothing", () => {
        const { fixture, list } = open();
        list.flush(
            { detail: 'The scans could not be listed.', status: 503 },
            { status: 503, statusText: 'Service Unavailable' }
        );
        fixture.detectChanges();

        expect(source()).toContain('The scans could not be listed.');
        expect(downloadButton().disabled).toBe(true);
    });

    it('says so when the download is refused, rather than saving nothing in silence', () => {
        const { fixture, http, list } = open();
        list.flush(asSchemaList('ScanSummary', [scan(11, 'completed')]));
        http.expectOne('/api/v1/scans/11').flush(detail(scan(11, 'completed'), true));
        fixture.detectChanges();

        const saved = captureSaves();
        downloadButton().click();
        http.expectOne('/api/v1/scans/11/sbom').flush(new Blob([]), { status: 404, statusText: 'Not Found' });
        fixture.detectChanges();

        expect(saved).toEqual([]);
        expect(source()).toContain('The download failed.');
        expect(downloadButton().disabled).toBe(false);
    });
});

describe("the repository card's SBOM button", () => {
    afterEach(() => TestBed.resetTestingModule());

    it('is named after its repository and opens the lookup for it', () => {
        const { http, page, dom } = mountOnRepositories(RepositoryList, { repositories: [repositorySummary(5)] });
        namedButton(dom(), 'Latest SBOM of repository-5').click();

        expect(page.sbomVisible()).toBe(true);
        expect(page.sbomRepo()?.id).toBe(5);
        expect(http.expectOne((call) => call.url === '/api/v1/scans').request.params.get('repo_id')).toBe('5');
    });
});
