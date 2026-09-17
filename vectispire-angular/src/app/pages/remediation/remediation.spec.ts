import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { I18nService } from '@/app/core/i18n/i18n.service';
import type { HighImpactFix, RemediationCoverage } from '@/app/core/api.models';
import { Remediation } from './remediation';
import { asSchema } from '@/app/core/testing/contract';

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

    const fix = (over: Partial<HighImpactFix>): HighImpactFix =>
        asSchema('HighImpactFix', {
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
                plan_total: 'Total du plan :',
                coverage_title: 'Ce que ce plan ne referme pas',
                coverage_summary: '{{covered}} des {{open}} constats ouverts se ferment par une montée de version. Les {{beyond}} autres se referment autrement :',
                coverage_all: 'Les {{open}} constats ouverts se ferment tous par une montée de version.',
                gap_secret: 'secrets exposés — à révoquer et à faire tourner ; on ne met pas un secret à jour.',
                gap_unpackaged: "vulnérabilités dont aucun paquet n'est nommé — il n'y a rien à monter.",
                gap_other: "constats d'un autre type."
            }
        });

        http = TestBed.inject(HttpTestingController);
        fixture = TestBed.createComponent(Remediation);
        fixture.detectChanges();
    });

    /** Le plan, la dette, l'aveu et les deux listes de cibles — dans l'ordre où la page les demande. */
    function answer(
        fixes: HighImpactFix[],
        debt: Record<string, unknown> = { totalOpenIssues: 9 },
        coverage: RemediationCoverage | null = null): void {

        plan().flush(fixes);
        http.expectOne((request) => request.url.includes('/remediation/debt')).flush(debt);

        // L'aveu est facultatif dans ces essais : les cas qui ne portent pas dessus doivent
        // pouvoir l'ignorer, exactement comme la page le fait quand le serveur ne répond pas.
        const admission = http.expectOne((request) => request.url.includes('/remediation/coverage'));
        if (coverage) {
            admission.flush(coverage);
        } else {
            admission.error(new ProgressEvent('failed'));
        }

        for (const request of http.match((r) => r.url.includes('/repositories') || r.url.includes('/containers'))) {
            request.flush([]);
        }
        fixture.detectChanges();
    }

    /** La requête de plan, quels que soient les paramètres qu'elle porte. */
    function plan() {
        return http.expectOne((request) => request.url.includes('/remediation/high-impact-fixes'));
    }

    it("garde l'ordre du serveur, qui est le classement par levier", () => {
        answer([
            fix({ packageName: 'log4j-core', leverageScore: 10.4 }),
            fix({ packageName: 'openssl', leverageScore: 3.2 })
        ], { totalOpenIssues: 9, criticalIssues: 2 });

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
        answer([fix({ recommendedVersion: null as unknown as string })], { totalOpenIssues: 1 });

        const text = fixture.nativeElement.textContent as string;
        expect(text).toContain('Aucune version corrigée publiée');
        expect(text).not.toContain('latest-patch');
    });

    it('survit à une dette indisponible, parce que le plan est le sujet', () => {
        plan().flush([fix({})]);
        http.expectOne((request) => request.url.includes('/remediation/debt'))
            .error(new ProgressEvent('failed'));
        http.expectOne((request) => request.url.includes('/remediation/coverage'))
            .error(new ProgressEvent('failed'));
        for (const request of http.match((r) => r.url.includes('/repositories') || r.url.includes('/containers'))) {
            request.flush([]);
        }
        fixture.detectChanges();

        expect(fixture.nativeElement.textContent).toContain('log4j-core');
        expect(fixture.componentInstance.error()).toBeNull();
    });

    it('demande la suite par paliers, sans dépasser le plafond', () => {
        answer(Array.from({ length: 10 }, (_, index) => fix({ packageName: `pkg-${index}` })));

        // Dix rendus sur dix demandés : il y a peut-être une suite, donc le bouton est là.
        expect(fixture.componentInstance.mayHaveMore()).toBe(true);
        fixture.componentInstance.showMore();
        fixture.detectChanges();

        // **Le palier est passé au serveur**, sans quoi le bouton rechargerait les mêmes dix
        // lignes et l'écran donnerait l'impression d'être bloqué.
        const second = plan();
        expect(second.request.params.get('limit')).toBe('25');
        second.flush(Array.from({ length: 25 }, (_, index) => fix({ packageName: `pkg-${index}` })));
        http.expectOne((request) => request.url.includes('/remediation/debt')).flush({ totalOpenIssues: 9 });
        http.expectOne((request) => request.url.includes('/remediation/coverage'))
            .error(new ProgressEvent('failed'));
        fixture.detectChanges();

        expect(fixture.componentInstance.wanted()).toBe(25);
    });

    it('recharge sur la cible choisie, et repart au premier palier', () => {
        answer([fix({})]);
        fixture.componentInstance.wanted.set(25);

        fixture.componentInstance.scope = 'repo:7';
        fixture.componentInstance.changeScope();

        // La portée est passée au serveur, et la taille repart à dix : le plan n'est plus le
        // même, et garder le palier précédent ferait croire à une continuité qui n'existe pas.
        const scoped = plan();
        expect(scoped.request.params.get('repoId')).toBe('7');
        expect(scoped.request.params.get('limit')).toBe('10');
        scoped.flush([]);
        http.expectOne((request) => request.url.includes('/remediation/debt')).flush({ totalOpenIssues: 0 });

        // **La portée est passée à l'aveu aussi.** Un aveu du parc entier posé sous le plan d'un
        // seul dépôt dirait « il en reste quatre cents » sous une liste qui en couvre trois.
        const admission = http.expectOne((request) => request.url.includes('/remediation/coverage'));
        expect(admission.request.params.get('repoId')).toBe('7');
        admission.error(new ProgressEvent('failed'));
        fixture.detectChanges();

        expect(fixture.componentInstance.wanted()).toBe(10);
    });

    it("dit pourquoi une seule action face à un retard chargé", () => {
        // **Le constat d'usage qui a motivé cet encart.** Une action, des centaines de constats
        // ouverts : le calcul est juste et l'écran avait l'air cassé. Il doit maintenant nommer
        // ce qui ne se ferme pas par une montée de version, et par quel geste on le referme.
        answer([fix({})], { totalOpenIssues: 412 }, {
            openFindings: 412,
            addressableByUpgrade: 12,
            beyondUpgrades: 400,
            gaps: [{ family: 'secret', findings: 399 }, { family: 'unpackaged', findings: 1 }]
        });

        const text = fixture.nativeElement.textContent as string;
        expect(text).toContain('Ce que ce plan ne referme pas');
        expect(text).toContain('12 des 412 constats ouverts');
        expect(text).toContain('Les 400 autres');
        expect(text).toContain('399');
        expect(text).toContain('à révoquer et à faire tourner');
        expect(text).toContain("il n'y a rien à monter");
    });

    it("se tait quand tout le retard se ferme par une montée de version", () => {
        answer([fix({})], { totalOpenIssues: 12 }, {
            openFindings: 12, addressableByUpgrade: 12, beyondUpgrades: 0, gaps: []
        });

        const text = fixture.nativeElement.textContent as string;
        expect(text).not.toContain('Ce que ce plan ne referme pas');
        expect(text).toContain('Les 12 constats ouverts se ferment tous');
    });

    it("nomme une famille qu'il ne connaît pas plutôt que d'afficher une clé", () => {
        // Un neuvième type de constat livré par un serveur plus récent que cet écran : il doit
        // être compté et dit faute de mieux, jamais rendu comme `remediation.gap_neuvieme`.
        answer([fix({})], { totalOpenIssues: 5 }, {
            openFindings: 5, addressableByUpgrade: 4, beyondUpgrades: 1,
            gaps: [{ family: 'runtime_drift', findings: 1 }]
        });

        const text = fixture.nativeElement.textContent as string;
        expect(text).toContain("constats d'un autre type");
        expect(text).not.toContain('remediation.gap');
    });

    it("n'affiche aucun aveu quand le serveur n'a pas répondu, et garde le plan", () => {
        answer([fix({})], { totalOpenIssues: 9 });

        const text = fixture.nativeElement.textContent as string;
        expect(text).toContain('log4j-core');
        expect(text).not.toContain('Ce que ce plan ne referme pas');
        expect(fixture.componentInstance.error()).toBeNull();
    });

    it('distingue « rien à faire » de « rien de calculable »', () => {
        answer([], { totalOpenIssues: 4 });

        // Quatre constats ouverts et aucune ligne de plan : le message doit expliquer que le
        // plan ne classe que ce qu'une montée de version ferme, sans quoi l'écran a l'air cassé.
        const text = fixture.nativeElement.textContent as string;
        expect(text).toContain('Rien à monter de version.');
        expect(text).toContain('4');
    });
});
