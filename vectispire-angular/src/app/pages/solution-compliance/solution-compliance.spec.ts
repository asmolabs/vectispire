import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { SolutionCompliance } from './solution-compliance';
import { useEnglish } from '@/app/core/testing/english';
import { SOLUTION_COMPLIANCE_NO_DATA } from '@/app/core/testing/scopes.fixtures';

describe("a solution's compliance", () => {
    let fixture: ComponentFixture<SolutionCompliance>;
    let http: HttpTestingController;

    async function open(answer: (request: ReturnType<HttpTestingController['expectOne']>) => void): Promise<void> {
        useEnglish();
        fixture = TestBed.createComponent(SolutionCompliance);
        fixture.componentRef.setInput('solutionId', '2');
        http = TestBed.inject(HttpTestingController);
        fixture.autoDetectChanges();
        await fixture.whenStable();
        answer(http.expectOne({ method: 'GET', url: '/api/v1/solutions/2/compliance' }));
        await fixture.whenStable();
    }

    const text = (selector: string) =>
        (fixture.nativeElement as HTMLElement).querySelector(selector)?.textContent?.replace(/\s+/g, ' ').trim() ?? '';

    beforeEach(async () => {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [SolutionCompliance],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();
    }, 20_000);

    it('draws the solution scope, and a score over nothing scanned as no data', async () => {
        await open((request) => request.flush(SOLUTION_COMPLIANCE_NO_DATA));

        expect(text('[data-testid="solution-title"]')).toBe('Compliance and score — Mobile');
        expect(text('[data-testid="scope-target-count"]')).toBe('Computed over 1 target.');
        // The server grades a scope nobody scanned NO_DATA with a null score; it used to answer 100, A+.
        expect(text('[data-testid="scorecard-score"]')).toBe('—');
        expect(text('[data-testid="scorecard-grade"]')).toBe('No data');
        expect(text('[data-testid="framework-NIS_2"]')).toContain('No data');
    });

    it('shows the not-found state on a 404', async () => {
        await open((request) =>
            request.flush(
                { title: 'Not Found', status: 404, detail: 'Solution not found.' },
                { status: 404, statusText: 'Not Found' }
            )
        );

        expect(text('[data-testid="not-found"]')).toBe(
            'This solution does not exist, or you see none of its repositories and images.'
        );
        expect(text('[data-testid="scorecard"]')).toBe('');
    });
});
