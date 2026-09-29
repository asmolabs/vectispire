import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { beforeEach, describe, expect, it } from 'vitest';
import { asSchemaList } from '@/app/core/testing/contract';
import { useEnglish } from '@/app/core/testing/english';
import { SarifImports } from './sarif-imports';

/**
 * A repository's SARIF import history: the evidence behind every imported issue. Read-only — the
 * uploads come from CI — and a repository outside the reader's visibility reads as absent.
 */
describe("a repository's SARIF imports", () => {
    let fixture: ComponentFixture<SarifImports>;
    let http: HttpTestingController;

    const IMPORTS = asSchemaList('SarifImportView', [
        {
            id: 7,
            sourceId: 3,
            sourceSlug: 'payments-ci',
            repoId: 42,
            tools: ['SonarQube', 'Semgrep OSS'],
            documentSha256: 'f'.repeat(64),
            resultsCount: 12,
            createdCount: 5,
            resolvedCount: 2,
            reopenedCount: 1,
            importedAt: '2026-09-27T09:00:00Z',
            importedBy: 'ci-bot',
            apiKeyId: '5f0c3c1e-0000-4000-8000-000000000001'
        }
    ]);

    beforeEach(async () => {
        await TestBed.configureTestingModule({
            imports: [SarifImports],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting()]
        }).compileComponents();
        useEnglish();
        fixture = TestBed.createComponent(SarifImports);
        fixture.componentRef.setInput('repositoryId', 42);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
    });

    it('lists each import with its source, tools, counts and document hash', () => {
        http.expectOne('/api/v1/repositories/42/sarif-imports').flush(IMPORTS);
        fixture.detectChanges();

        const row = (fixture.nativeElement as HTMLElement).querySelector('[data-testid="sarif-import"]');
        const text = row?.textContent ?? '';
        expect(text).toContain('payments-ci');
        // One tag per tool, never a joined string: a tool whose name holds a comma stays one tool.
        const tools = Array.from(row?.querySelectorAll('[data-testid="sarif-import-tools"] p-tag') ?? []).map((tag) =>
            tag.textContent?.trim()
        );
        expect(tools).toEqual(['SonarQube', 'Semgrep OSS']);
        expect(text).toContain('f'.repeat(64));
        expect(text).toContain('ci-bot');
        const cells = Array.from(row?.querySelectorAll('td') ?? []).map((cell) => cell.textContent?.trim());
        expect(cells.slice(3, 7)).toEqual(['12', '5', '2', '1']);
    });

    it('offers no upload', () => {
        http.expectOne('/api/v1/repositories/42/sarif-imports').flush([]);
        fixture.detectChanges();

        expect((fixture.nativeElement as HTMLElement).querySelector('input[type="file"], button')).toBeNull();
        expect(fixture.nativeElement.textContent).toContain('No SARIF report was imported');
    });

    it('reads a 404 as a repository that is not visible, and says nothing more', () => {
        http.expectOne('/api/v1/repositories/42/sarif-imports').flush(null, { status: 404, statusText: 'Not Found' });
        fixture.detectChanges();

        expect(fixture.nativeElement.textContent).toContain('does not exist or is not visible to you');
    });

    it("follows the input to another repository's history", () => {
        http.expectOne('/api/v1/repositories/42/sarif-imports').flush(IMPORTS);
        fixture.componentRef.setInput('repositoryId', 43);
        fixture.detectChanges();
        http.expectOne('/api/v1/repositories/43/sarif-imports').flush([]);
        fixture.detectChanges();

        expect(fixture.componentInstance.imports()).toEqual([]);
    });
});
