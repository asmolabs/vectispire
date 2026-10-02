import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
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
        fixture.detectChanges();

        expect(component.summary()?.evaluations.length).toBe(2);
        const nis2 = (fixture.nativeElement as HTMLElement).querySelector('[data-testid="framework-NIS_2"]');
        expect(nis2?.textContent).toContain('90%');
    });

    /**
     * The per-target matrix in the global view. It was guarded by `!selectedTarget()` while the global
     * view is `'ALL'`, a truthy string: the matrix the server sent was never drawn.
     */
    it('draws the per-target matrix in the global view, each row offering to narrow the page to its target', () => {
        fixture.detectChanges();
        http.expectOne('/api/v1/compliance/summary').flush({
            ...MOCK_SUMMARY,
            targets: [
                {
                    targetId: 'REPOSITORY:3',
                    name: 'billing',
                    type: 'REPOSITORY',
                    gateStatus: 'PASSED',
                    openIssuesCount: 0,
                    overdueCount: 0,
                    overallStatus: 'COMPLIANT',
                    overallScore: 95,
                    frameworkScores: { NIS_2: 95 }
                }
            ]
        });
        fixture.detectChanges();

        const row = (fixture.nativeElement as HTMLElement).querySelector('[data-testid="matrix-row"]');
        expect(row?.textContent).toContain('billing');
        row?.querySelector('button')?.click();
        expect(component.selectedTarget()).toBe('REPOSITORY:3');
        http.expectOne('/api/v1/compliance/summary?targetId=REPOSITORY:3');
    });

    /**
     * The PDF export asks for the scope the page shows. The global view's selector value is `'ALL'`,
     * and it was sent as `?targetId=ALL`: the server read it as the estate only because it tolerates
     * that word, audited the export as made "for ALL", and the file was saved under that name.
     */
    describe('PDF export', () => {
        const saved: string[] = [];
        beforeEach(() => {
            saved.length = 0;
            // happy-dom's anchor click navigates the window; the download name is what matters here.
            vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) {
                saved.push(this.download);
            });
        });

        const clickExport = () =>
            [...(fixture.nativeElement as HTMLElement).querySelectorAll<HTMLButtonElement>('button')]
                .find((b) => b.querySelector('.pi-file-pdf'))!
                .click();

        it('asks for the estate, not a target named ALL, from the global view', () => {
            fixture.detectChanges();
            http.expectOne('/api/v1/compliance/summary').flush(MOCK_SUMMARY);
            fixture.detectChanges();

            clickExport();
            http.expectOne('/api/v1/compliance/export.pdf').flush(new Blob(['%PDF']));

            http.verify();
            expect(saved).toEqual(['vectispire-compliance-report.pdf']);
        });

        it('asks for the selected target by its id', () => {
            fixture.detectChanges();
            http.expectOne('/api/v1/compliance/summary').flush(MOCK_SUMMARY);
            component.onTargetChange('REPOSITORY:3');
            http.expectOne('/api/v1/compliance/summary?targetId=REPOSITORY:3').flush(MOCK_SUMMARY);
            fixture.detectChanges();

            clickExport();
            http.expectOne('/api/v1/compliance/export.pdf?targetId=REPOSITORY%3A3').flush(new Blob(['%PDF']));

            http.verify();
            expect(saved).toEqual(['vectispire-compliance-REPOSITORY-3.pdf']);
        });
    });

    /** The four documents the header offers, each saved under its own name and type. */
    describe('document downloads', () => {
        const saved: { name: string; blob: Blob }[] = [];
        let blobs: Blob[];

        beforeEach(() => {
            saved.length = 0;
            blobs = [];
            vi.spyOn(URL, 'createObjectURL').mockImplementation((blob: Blob | MediaSource) => {
                blobs.push(blob as Blob);
                return `blob:test/${blobs.length}`;
            });
            vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) {
                saved.push({ name: this.download, blob: blobs[blobs.length - 1] });
            });
            fixture.detectChanges();
            http.expectOne('/api/v1/compliance/summary').flush(MOCK_SUMMARY);
            fixture.detectChanges();
        });

        afterEach(() => vi.restoreAllMocks());

        const click = (label: string) =>
            [...(fixture.nativeElement as HTMLElement).querySelectorAll<HTMLButtonElement>('button')]
                .find((b) => b.textContent.includes(label))!
                .click();

        it('saves the aggregate OpenVEX, CSAF and CycloneDX as indented JSON', async () => {
            click('compliance.export_vex');
            http.expectOne('/api/v1/vex/aggregate.json').flush({ statements: [] });
            click('compliance.export_csaf');
            http.expectOne((r) => r.url.includes('/csaf/')).flush({ document: {} });
            click('compliance.export_cyclonedx');
            http.expectOne((r) => r.url.includes('cyclonedx')).flush({ bomFormat: 'CycloneDX' });

            expect(saved.map((file) => file.name)).toEqual([
                'vectispire-aggregate-openvex.json',
                'vectispire-aggregate-csaf.json',
                'vectispire-aggregate-cyclonedx-vex.json'
            ]);
            expect(saved.every((file) => file.blob.type === 'application/json')).toBe(true);
            expect(await saved[0].blob.text()).toBe('{\n  "statements": []\n}');
        });

        it('saves the signing key as a PEM file', async () => {
            click('compliance.cosign_key');
            http.expectOne('/api/v1/crypto/public-key.pub').flush('-----BEGIN PUBLIC KEY-----');

            expect(saved.map((file) => file.name)).toEqual(['vectispire-signing-key.pub']);
            expect(saved[0].blob.type).toBe('application/x-pem-file');
            expect(await saved[0].blob.text()).toBe('-----BEGIN PUBLIC KEY-----');
        });
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
