import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { Compliance } from './compliance';
import { I18nService } from '../../core/i18n/i18n.service';
import { asSchema } from '@/app/core/testing/contract';

describe('Compliance Page', () => {
    let fixture: ComponentFixture<Compliance>;
    let component: Compliance;
    let http: HttpTestingController;

    const MOCK_SUMMARY = asSchema('ComplianceSummary', {
        evaluations: [
            {
                framework: 'NIS_2',
                scorePercentage: 90,
                overallStatus: 'COMPLIANT',
                controls: [
                    {
                        control: {
                            id: 'NIS2-ART21-VULN',
                            name: 'Vulnerability Handling',
                            requirement: 'All known vulnerabilities must be tracked.',
                            category: 'VULNERABILITY_MANAGEMENT'
                        },
                        status: 'COMPLIANT',
                        scorePercentage: 100,
                        details: 'No critical CVEs.',
                        remediationGuidance: 'Maintain continuous scanning.'
                    }
                ]
            },
            {
                framework: 'DORA',
                scorePercentage: 85,
                overallStatus: 'PARTIAL',
                controls: []
            }
        ],
        mttr: {
            mttrBySeverityDays: { critical: 5.0, high: 14.0 },
            overallMttrDays: 9.5,
            resolvedCount: 12
        },
        overdueCount: 0,
        dueSoonCount: 2,
        totalMonitoredTargets: 5,
        passingGateTargets: 5,
        observedTargets: 4,
        freshTargets: 3
    });

    beforeEach(async () => {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [Compliance],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), I18nService]
        }).compileComponents();

        fixture = TestBed.createComponent(Compliance);
        component = fixture.componentInstance;
        http = TestBed.inject(HttpTestingController);
    });

    it('loads and displays compliance summary', () => {
        fixture.detectChanges();
        const req = http.expectOne('/api/v1/compliance/summary');
        expect(req.request.method).toBe('GET');
        req.flush(MOCK_SUMMARY);

        expect(component.summary()).not.toBeNull();
        expect(component.summary()?.evaluations.length).toBe(2);
        expect(component.activeEvaluation()?.framework).toBe('NIS_2');
        expect(component.activeEvaluation()?.scorePercentage).toBe(90);
    });

    it('switches active framework on selection', () => {
        fixture.detectChanges();
        http.expectOne('/api/v1/compliance/summary').flush(MOCK_SUMMARY);

        component.selectFramework('DORA');
        expect(component.selectedFramework()).toBe('DORA');
        expect(component.activeEvaluation()?.framework).toBe('DORA');
    });

    /**
     * Freshness, and the one green that should raise an alarm.
     *
     * A target never scanned presents no known vulnerability. On a table that counts findings it is
     * green — and the server already sent what it takes to say so, `observedTargets` and
     * `freshTargets`, which nothing read.
     */
    it('separates a stale observation from an absent one', () => {
        http.expectOne('/api/v1/compliance/summary').flush(MOCK_SUMMARY);
        fixture.detectChanges();

        // 3 fresh targets of 5 monitored, and 5 − 4 observed = 1 never looked at.
        expect(fixture.componentInstance.freshnessRate()).toBe(60);
        expect(fixture.componentInstance.neverObserved()).toBe(1);
        expect(fixture.componentInstance.freshnessTone()).toBe('text-red-500');
    });

    it('does not shout on an empty estate: a hundred per cent, not zero', () => {
        http.expectOne('/api/v1/compliance/summary').flush({
            ...MOCK_SUMMARY,
            totalMonitoredTargets: 0,
            passingGateTargets: 0,
            observedTargets: 0,
            freshTargets: 0
        });
        fixture.detectChanges();

        // Zero would read as an alarm where there is nothing to observe, and an alarm that fires
        // on a fresh deployment teaches its reader to ignore the one that matters.
        expect(fixture.componentInstance.freshnessRate()).toBe(100);
        expect(fixture.componentInstance.neverObserved()).toBe(0);
    });

    /**
     * A file picked in the import dialog enables Import — **without a `detectChanges` from the test.**
     *
     * The file is read in `FileReader.onload`, a callback no template event wraps. While the text
     * was a plain field, a zoneless application rendered nothing after it: the textarea stayed
     * empty and the button disabled, although the component held the document. Calling
     * `detectChanges` here would hide exactly that, so the test only waits.
     */
    it('enables Import once a picked file has been read', async () => {
        fixture.autoDetectChanges();
        http.expectOne('/api/v1/compliance/summary').flush(MOCK_SUMMARY);
        component.openImport();
        await fixture.whenStable();

        const input = document.getElementById('vex-import-file') as HTMLInputElement;
        const textarea = document.getElementById('vex-import-json') as HTMLTextAreaElement;
        const importButton = () =>
            [...document.querySelectorAll<HTMLButtonElement>('button')].find((b) => b.querySelector('.pi-check'))!;
        expect(importButton().disabled).toBe(true);

        const vex = '{ "statements": [] }';
        Object.defineProperty(input, 'files', { value: [new File([vex], 'vex.json')] });
        input.dispatchEvent(new Event('change'));

        await vi.waitFor(() => {
            expect(importButton().disabled).toBe(false);
            expect(textarea.value).toBe(vex);
        });
    });
});
