import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { beforeEach, describe, expect, it } from 'vitest';
import { asSchemaList } from '@/app/core/testing/contract';
import { useEnglish, useFrench } from '@/app/core/testing/english';
import { missingFromBundles } from '@/app/core/testing/bundles';
import { PACKAGES_STATE_KEYS, ReportImports } from './report-imports';

/**
 * A repository's latest coverage and test report (decision 0032 §7): figures a checklist reads,
 * with where they came from. Read-only, and a repository outside the reader's visibility reads as
 * absent — on both panels, since both routes answer 404.
 */
describe("a repository's latest coverage and test report", () => {
    let fixture: ComponentFixture<ReportImports>;
    let http: HttpTestingController;

    const COVERAGE = asSchemaList('CoverageImportView', [
        {
            id: 9,
            sourceId: 3,
            sourceSlug: 'payments-ci',
            repoId: 42,
            format: 'jacoco',
            toolVersion: '0.8.14',
            linesCovered: 250,
            linesTotal: 300,
            branchesCovered: 40,
            branchesTotal: 64,
            commit: '3f2a9c1',
            branch: 'main',
            documentSha256: 'a'.repeat(64),
            importedAt: '2026-09-27T09:00:00Z',
            importedBy: 'ci-bot',
            apiKeyId: '5f0c3c1e-0000-4000-8000-000000000001'
        },
        {
            id: 8,
            sourceId: 3,
            sourceSlug: 'older-ci',
            repoId: 42,
            format: 'lcov',
            toolVersion: null,
            linesCovered: 1,
            linesTotal: 2,
            branchesCovered: null,
            branchesTotal: null,
            commit: null,
            branch: null,
            documentSha256: 'b'.repeat(64),
            importedAt: '2026-09-20T09:00:00Z',
            importedBy: 'ci-bot',
            apiKeyId: null
        }
    ]);

    const TESTS = asSchemaList('TestReportImportView', [
        {
            id: 5,
            sourceId: 3,
            sourceSlug: 'payments-ci',
            repoId: 42,
            format: 'junit-zip',
            documentsCount: 3,
            suitesCount: 12,
            testsCount: 480,
            failuresCount: 2,
            errorsCount: 1,
            skippedCount: 7,
            commit: '3f2a9c1',
            branch: 'main',
            documentSha256: 'c'.repeat(64),
            importedAt: '2026-09-27T09:05:00Z',
            importedBy: 'ci-bot',
            apiKeyId: '5f0c3c1e-0000-4000-8000-000000000001'
        }
    ]);

    beforeEach(async () => {
        await TestBed.configureTestingModule({
            imports: [ReportImports],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting()]
        }).compileComponents();
        useEnglish();
        fixture = TestBed.createComponent(ReportImports);
        fixture.componentRef.setInput('repositoryId', 42);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
    });

    const dom = () => fixture.nativeElement as HTMLElement;
    const text = (selector: string) => dom().querySelector(selector)?.textContent?.trim() ?? '';

    function answer(coverage: unknown[], tests: unknown[]): void {
        http.expectOne('/api/v1/repositories/42/coverage-imports').flush(coverage);
        http.expectOne('/api/v1/repositories/42/test-report-imports').flush(tests);
        fixture.detectChanges();
    }

    it('shows the newest coverage as percentages of lines and branches, with its provenance', () => {
        answer(COVERAGE, TESTS);

        expect(text('[data-testid="coverage-lines"]')).toBe('83.3% (250 / 300)');
        expect(text('[data-testid="coverage-branches"]')).toBe('62.5% (40 / 64)');
        const panel = text('[data-testid="latest-coverage"]');
        expect(panel).toContain('jacoco');
        expect(panel).toContain('0.8.14');
        expect(panel).toContain('3f2a9c1');
        expect(panel).toContain('main');
        expect(panel).toContain('27/09/2026');
        expect(panel).toContain('payments-ci');
        // The newest only: the older import is history, not the figure.
        expect(panel).not.toContain('older-ci');
    });

    it('spaces the percent sign as French does, with a space that does not break', () => {
        // The bundles wrote "{{percent}} %" in both languages, other screens glued the sign: French
        // read "50%" here and "50 %" there, and English got the French space.
        useFrench();
        answer(COVERAGE, TESTS);

        expect(text('[data-testid="coverage-lines"]')).toBe('83,3 % (250 / 300)');
    });

    it('says branches were not counted rather than showing zero', () => {
        answer([COVERAGE[1]], []);

        expect(text('[data-testid="coverage-lines"]')).toBe('50% (1 / 2)');
        expect(text('[data-testid="coverage-branches"]')).toBe('Not counted by the report');
    });

    // The window showed nothing for packagesState: "not kept" and "imported before packages were kept"
    // both read as a report with no package, and a scoped rule's empty measure had no explanation.
    it('says whether the packages were kept, and why not', () => {
        answer([{ ...COVERAGE[0], packagesState: 'too_many' }], []);

        expect(text('[data-testid="coverage-packages"]')).toBe('Not kept: more than 10,000 packages');
    });

    it('says the packages were kept, in French too', () => {
        useFrench();
        answer([{ ...COVERAGE[0], packagesState: 'kept' }], []);

        expect(text('[data-testid="coverage-packages"]')).toBe('Conservés par paquet');
    });

    it('reads an import from before packages were kept as unrecorded, not as none', () => {
        answer([{ ...COVERAGE[0], packagesState: null }], []);

        expect(text('[data-testid="coverage-packages"]')).toContain('Not recorded');
    });

    it('shows a state this client does not know as sent, never as a key', () => {
        answer([{ ...COVERAGE[0], packagesState: 'truncated' }], []);

        expect(text('[data-testid="coverage-packages"]')).toBe('truncated');
    });

    it('spells every packages state with keys both bundles hold', () => {
        expect(
            missingFromBundles([...Object.values(PACKAGES_STATE_KEYS), 'report_imports.packages_unrecorded'])
        ).toEqual([]);
    });

    it('shows the newest test report as the view counts it', () => {
        answer([], TESTS);

        expect(text('[data-testid="tests-count"]')).toBe('480');
        expect(text('[data-testid="failures-count"]')).toBe('2');
        expect(text('[data-testid="errors-count"]')).toBe('1');
        expect(text('[data-testid="skipped-count"]')).toBe('7');
        const panel = text('[data-testid="latest-test-report"]');
        expect(panel).toContain('junit-zip');
        expect(panel).toContain('27/09/2026');
        expect(panel).toContain('payments-ci');
    });

    it('says so when nothing was imported, and offers no upload', () => {
        answer([], []);

        expect(text('[data-testid="no-coverage"]')).toBe('No coverage report was imported for this repository.');
        expect(text('[data-testid="no-test-report"]')).toBe('No test report was imported for this repository.');
        expect(dom().querySelector('input[type="file"], button')).toBeNull();
    });

    it('reads a 404 as a repository that is not visible, and says nothing more', () => {
        http.expectOne('/api/v1/repositories/42/coverage-imports').flush(null, {
            status: 404,
            statusText: 'Not Found'
        });
        http.expectOne('/api/v1/repositories/42/test-report-imports').flush(null, {
            status: 404,
            statusText: 'Not Found'
        });
        fixture.detectChanges();

        expect(text('[data-testid="latest-coverage"]')).toContain('does not exist or is not visible to you');
        expect(text('[data-testid="latest-test-report"]')).toContain('does not exist or is not visible to you');
        expect(dom().querySelector('[data-testid="no-coverage"]')).toBeNull();
    });

    it("shows the server's explanation for another failure", () => {
        http.expectOne('/api/v1/repositories/42/coverage-imports').flush(
            { detail: 'The coverage history is unavailable.' },
            { status: 503, statusText: 'Service Unavailable' }
        );
        http.expectOne('/api/v1/repositories/42/test-report-imports').flush([]);
        fixture.detectChanges();

        expect(text('[data-testid="latest-coverage"]')).toContain('The coverage history is unavailable.');
        expect(dom().querySelector('[data-testid="no-test-report"]')).not.toBeNull();
    });

    it("follows the input to another repository's reports", () => {
        answer(COVERAGE, TESTS);
        fixture.componentRef.setInput('repositoryId', 43);
        fixture.detectChanges();
        http.expectOne('/api/v1/repositories/43/coverage-imports').flush([]);
        http.expectOne('/api/v1/repositories/43/test-report-imports').flush([]);
        fixture.detectChanges();

        expect(fixture.componentInstance.coverage()).toBeNull();
        expect(dom().querySelector('[data-testid="no-coverage"]')).not.toBeNull();
    });
});
