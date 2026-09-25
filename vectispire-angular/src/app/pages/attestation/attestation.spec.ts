import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { I18nService } from '@/app/core/i18n/i18n.service';
import { Attestation } from './attestation';
import { asSchema } from '@/app/core/testing/contract';

/**
 * The auditor's page.
 *
 * <p>Two things have to hold or the page is worse than nothing: a broken chain must be impossible
 * to miss, and a compliance call that fails must not take the chain verdict down with it. The
 * chain is the one claim here that is a proof rather than a measurement.
 */
describe('the attestation', () => {
    let fixture: ComponentFixture<Attestation>;
    let http: HttpTestingController;

    beforeEach(async () => {
        await TestBed.configureTestingModule({
            imports: [Attestation],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        // The labels the page shows: without them the pipe renders the key, and an assertion on
        // "attestation.chain_broken" does not prove a reader would see anything at all.
        TestBed.inject(I18nService).translations.set({
            attestation: {
                title: 'Attestation',
                established: 'État établi le',
                targets: 'cibles suivies',
                download: 'Télécharger',
                recheck: 'Revérifier',
                open_audit_log: 'Journal',
                chain_intact: "Chaîne d'audit intacte",
                chain_broken: "Chaîne d'audit rompue",
                entries: 'entrées',
                verified: 'vérifiées',
                unverifiable: 'antérieures',
                frameworks: 'Référentiels',
                frameworks_note: '',
                no_compliance: '',
                bundle: 'Paquet',
                bundle_desc: ''
            }
        });

        fixture = TestBed.createComponent(Attestation);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
    }, 20_000);

    function chain(intact: boolean, broken: string | null = null): void {
        http.expectOne('/api/v1/audit-log/verify').flush(
            // `mirrorConfigured` does not exist: the field is called `mirrored`, and three counters
            // the server always sends were missing. This screen reads none of them — the fixture
            // simply described a response that never arrives.
            asSchema('Verification', {
                total: 48219,
                unverifiable: 0,
                verified: 48219,
                intact,
                broken,
                mirrored: true,
                missingFromTable: 0,
                missingFromMirror: 0
            })
        );
    }

    function compliance(): void {
        http.expectOne((c) => c.url === '/api/v1/compliance/summary').flush(
            asSchema('ComplianceSummary', {
                evaluations: [
                    { framework: 'SOC_2', scorePercentage: 90, overallStatus: 'COMPLIANT', controls: [] },
                    { framework: 'NIS_2', scorePercentage: 92, overallStatus: 'COMPLIANT', controls: [] },
                    { framework: 'PCI_DSS', scorePercentage: 64, overallStatus: 'PARTIAL', controls: [] }
                ],
                mttr: { mttrBySeverityDays: {}, overallMttrDays: null, resolvedCount: 0 },
                overdueCount: 0,
                dueSoonCount: 0,
                totalMonitoredTargets: 46,
                passingGateTargets: 46,
                observedTargets: 46,
                freshTargets: 46
            })
        );
    }

    it('leads with the chain, and says how many entries it stands on', () => {
        chain(true);
        compliance();
        fixture.detectChanges();

        const text = fixture.nativeElement.textContent;
        expect(text).toContain("Chaîne d'audit intacte");
        expect(text).toContain('48219');
        expect(text).toContain('46');
    });

    it('a broken chain is impossible to miss, and names where it broke', () => {
        // **The case that justifies the page.** A broken chain shown as a detail is worth as much
        // as an unverified chain: the screen must say so, and say where.
        chain(false, 'entry 41207 does not match its predecessor');
        compliance();
        fixture.detectChanges();

        const text = fixture.nativeElement.textContent;
        expect(text).toContain("Chaîne d'audit rompue");
        expect(text).toContain('entry 41207 does not match its predecessor');
        expect(text).not.toContain("Chaîne d'audit intacte");
    });

    it('orders the frameworks so two screenshots can be compared', () => {
        chain(true);
        compliance();
        fixture.detectChanges();

        // Rendered in the fixed order, not in the server's: a grid whose columns move between two
        // loads does not compare with last month's printout.
        expect(fixture.componentInstance.frameworks().map((f) => f.framework)).toEqual(['NIS_2', 'PCI_DSS', 'SOC_2']);
    });

    it('keeps the chain verdict when compliance cannot be read', () => {
        chain(true);
        http.expectOne((c) => c.url === '/api/v1/compliance/summary').flush('nope', {
            status: 500,
            statusText: 'Server Error'
        });
        fixture.detectChanges();

        expect(fixture.nativeElement.textContent).toContain("Chaîne d'audit intacte");
        expect(fixture.componentInstance.compliance()).toBeNull();
    });
});
