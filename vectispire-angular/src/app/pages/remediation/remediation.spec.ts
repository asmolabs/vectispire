import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { I18nService } from '@/app/core/i18n/i18n.service';
import type { HighImpactFix } from '@/app/core/api.models';
import { Remediation } from './remediation';

/**
 * L'ordre de travail.
 *
 * <p>Trois choses doivent tenir, sans quoi la page conseille mal — ce qui est pire que se taire.
 * L'ordre du serveur doit être celui de l'écran ; une mise à jour sans version corrigée connue
 * doit se dire autrement qu'une mise à jour disponible ; et une dette indisponible ne doit pas
 * emporter le plan, qui est le sujet de la page.
 */
describe('le plan de remédiation', () => {
    let fixture: ComponentFixture<Remediation>;
    let http: HttpTestingController;

    const fix = (over: Partial<HighImpactFix>): HighImpactFix => ({
        packageName: 'log4j-core',
        currentVersion: '2.14.1',
        recommendedVersion: '2.17.1',
        cveCountResolved: 3,
        criticalCveCount: 1,
        highCveCount: 2,
        estimatedHours: 1.3,
        leverageScore: 10.4,
        affectedCves: ['CVE-2021-44228'],
        affectedTargetNames: ['alpha'],
        ...over
    });

    beforeEach(async () => {
        await TestBed.configureTestingModule({
            imports: [Remediation],
            providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        // Sans dictionnaire, le pipe rend la clé : une assertion sur « aucune version corrigée »
        // ne prouverait alors rien de ce qu'un lecteur voit.
        TestBed.inject(I18nService).translations.set({
            common: { loading: 'Chargement…' },
            severities: { critical: 'critiques' },
            remediation: {
                title: 'Plan de remédiation', subtitle: '—', open_findings: 'constats ouverts',
                critical: 'critiques', person_days: 'jours-personne', closed_by_plan: 'fermés',
                empty_title: 'Rien à monter de version.', empty_help: '—',
                no_fixed_version: 'Aucune version corrigée publiée', closes: 'ferme',
                targets: 'cibles', leverage: 'levier', details: 'Détail',
                cves: 'Vulnérabilités fermées', affected_targets: 'Cibles concernées',
                plan_total: 'Total du plan :'
            }
        });

        http = TestBed.inject(HttpTestingController);
        fixture = TestBed.createComponent(Remediation);
        fixture.detectChanges();
    });

    it("garde l'ordre du serveur, qui est le classement par levier", () => {
        http.expectOne('/api/v1/remediation/high-impact-fixes').flush([
            fix({ packageName: 'log4j-core', leverageScore: 10.4 }),
            fix({ packageName: 'openssl', leverageScore: 3.2 })
        ]);
        http.expectOne('/api/v1/remediation/debt').flush({ totalOpenIssues: 9, criticalIssues: 2 });
        fixture.detectChanges();

        // **L'ordre est l'information.** Une page qui range par levier puis réordonne par nom,
        // ou qu'un `track` ferait glisser, transforme un ordre de travail en liste.
        const text = fixture.nativeElement.textContent as string;
        expect(text.indexOf('log4j-core')).toBeLessThan(text.indexOf('openssl'));
        expect(text).toContain('2.14.1');
        expect(text).toContain('2.17.1');
    });

    it("dit qu'aucune version ne corrige, au lieu de conseiller une mise à jour inexistante", () => {
        // **Le défaut que ceci ferme, un cran plus loin.** Le serveur renvoyait la chaîne
        // « latest-patch » pour tout le monde, et le tableau de bord l'affichait derrière une
        // flèche. Maintenant qu'il peut ne rien renvoyer, l'écran doit dire quoi.
        http.expectOne('/api/v1/remediation/high-impact-fixes')
            .flush([fix({ recommendedVersion: null as unknown as string })]);
        http.expectOne('/api/v1/remediation/debt').flush({ totalOpenIssues: 1 });
        fixture.detectChanges();

        const text = fixture.nativeElement.textContent as string;
        expect(text).toContain('Aucune version corrigée publiée');
        expect(text).not.toContain('latest-patch');
    });

    it('survit à une dette indisponible, parce que le plan est le sujet', () => {
        http.expectOne('/api/v1/remediation/high-impact-fixes').flush([fix({})]);
        http.expectOne('/api/v1/remediation/debt').error(new ProgressEvent('failed'));
        fixture.detectChanges();

        expect(fixture.nativeElement.textContent).toContain('log4j-core');
        expect(fixture.componentInstance.error()).toBeNull();
    });

    it('distingue « rien à faire » de « rien de calculable »', () => {
        http.expectOne('/api/v1/remediation/high-impact-fixes').flush([]);
        http.expectOne('/api/v1/remediation/debt').flush({ totalOpenIssues: 4 });
        fixture.detectChanges();

        // Quatre constats ouverts et aucune ligne de plan : le message doit expliquer que le
        // plan ne classe que ce qu'une montée de version ferme, sans quoi l'écran a l'air cassé.
        const text = fixture.nativeElement.textContent as string;
        expect(text).toContain('Rien à monter de version.');
        expect(text).toContain('4');
    });
});
