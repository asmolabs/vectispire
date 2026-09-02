import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { I18nService } from '@/app/core/i18n/i18n.service';
import { Attestation } from './attestation';

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
            providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        // Les libellés que la page affiche : sans eux le pipe rend la clé, et une assertion sur
        // « attestation.chain_broken » ne prouve pas qu'un lecteur verrait quoi que ce soit.
        TestBed.inject(I18nService).translations.set({
            attestation: {
                title: 'Attestation', established: 'État établi le', targets: 'cibles suivies',
                download: 'Télécharger', recheck: 'Revérifier', open_audit_log: 'Journal',
                chain_intact: "Chaîne d'audit intacte", chain_broken: "Chaîne d'audit rompue",
                entries: 'entrées', verified: 'vérifiées', unverifiable: 'antérieures',
                frameworks: 'Référentiels', frameworks_note: '', no_compliance: '',
                bundle: 'Paquet', bundle_desc: ''
            }
        });

        fixture = TestBed.createComponent(Attestation);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
    }, 20_000);

    function chain(intact: boolean, broken: string | null = null): void {
        http.expectOne('/api/v1/audit-log/verify').flush({
            total: 48219, unverifiable: 0, verified: 48219, intact, broken, mirrorConfigured: true
        });
    }

    function compliance(): void {
        http.expectOne((c) => c.url === '/api/v1/compliance/summary').flush({
            evaluations: [
                { framework: 'SOC_2', scorePercentage: 90, overallStatus: 'COMPLIANT', controls: [] },
                { framework: 'NIS_2', scorePercentage: 92, overallStatus: 'COMPLIANT', controls: [] },
                { framework: 'PCI_DSS', scorePercentage: 64, overallStatus: 'PARTIAL', controls: [] }
            ],
            mttr: { mttrBySeverityDays: {}, overallMttrDays: null, resolvedCount: 0 },
            overdueCount: 0, dueSoonCount: 0, totalMonitoredTargets: 46
        });
    }

    it('leads with the chain, and says how many entries it stands on', () => {
        chain(true);
        compliance();
        fixture.detectChanges();

        const text = fixture.nativeElement.textContent;
        expect(text).toContain('Chaîne d\'audit intacte');
        expect(text).toContain('48219');
        expect(text).toContain('46');
    });

    it('a broken chain is impossible to miss, and names where it broke', () => {
        // **Le cas qui justifie la page.** Une chaîne rompue affichée comme un détail vaut une
        // chaîne non vérifiée : l'écran doit le dire, et dire où.
        chain(false, 'entry 41207 does not match its predecessor');
        compliance();
        fixture.detectChanges();

        const text = fixture.nativeElement.textContent;
        expect(text).toContain('Chaîne d\'audit rompue');
        expect(text).toContain('entry 41207 does not match its predecessor');
        expect(text).not.toContain('Chaîne d\'audit intacte');
    });

    it('orders the frameworks so two screenshots can be compared', () => {
        chain(true);
        compliance();
        fixture.detectChanges();

        // Rendus dans l'ordre fixe, pas dans celui du serveur : une grille dont les colonnes
        // bougent entre deux chargements ne se compare pas au relevé du mois dernier.
        expect(fixture.componentInstance.frameworks().map((f) => f.framework))
            .toEqual(['NIS_2', 'PCI_DSS', 'SOC_2']);
    });

    it('keeps the chain verdict when compliance cannot be read', () => {
        chain(true);
        http.expectOne((c) => c.url === '/api/v1/compliance/summary')
            .flush('nope', { status: 500, statusText: 'Server Error' });
        fixture.detectChanges();

        expect(fixture.nativeElement.textContent).toContain('Chaîne d\'audit intacte');
        expect(fixture.componentInstance.compliance()).toBeNull();
    });
});
