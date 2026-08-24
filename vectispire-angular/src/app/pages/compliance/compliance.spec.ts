import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { beforeEach, describe, expect, it } from 'vitest';
import { Compliance } from './compliance';
import { I18nService } from '../../core/i18n/i18n.service';

describe('Compliance Page', () => {
    let fixture: ComponentFixture<Compliance>;
    let component: Compliance;
    let http: HttpTestingController;

    const MOCK_SUMMARY = {
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
        passingGateTargets: 5
    };

    beforeEach(async () => {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [Compliance],
            providers: [provideHttpClient(), provideHttpClientTesting(), I18nService]
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
});
