import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { OwaspGridComponent } from './owasp-grid';
import type { OwaspGrid } from '@/app/core/api.models';
import { I18nService } from '@/app/core/i18n/i18n.service';
import { asSchema } from '@/app/core/testing/contract';

/**
 * La grille des dix, et la distinction qui la justifie.
 *
 * <p><b>« Rien trouvé » et « rien ne regarde » produisent le même vert.</b> Deux états ne peuvent
 * pas les séparer, d'où quatre — et les assertions ici portent sur les trois qui ne sont pas
 * « rien trouvé », parce que ce sont ceux qu'une grille à deux états se trompe en ayant l'air
 * juste.
 */
describe('la grille OWASP', () => {
    let fixture: ComponentFixture<OwaspGridComponent>;
    let http: HttpTestingController;

    function line(id: string, state: string, findings = 0) {
        return { id, title: id, state, findings, because: 'parce que.' };
    }

    const GRID = asSchema('DeclaredGrid', {
            lines: [
                line('A01', 'NOT_COVERED'),
                line('A05', 'FINDINGS', 3),
                line('A06', 'NO_FINDING'),
                line('A07', 'NOT_MEASURED')
            ],
            covered: 3,
            withFindings: 1,
            unmeasured: 1
    });

    beforeEach(async () => {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [OwaspGridComponent],
            providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        fixture = TestBed.createComponent(OwaspGridComponent);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
        http.expectOne((call) => call.url === '/api/v1/owasp/coverage').flush(GRID);
        fixture.detectChanges();
    }, 20_000);

    it('ne peint pas « aucun scanner ici » de la couleur de « rien trouvé »', () => {
        const component = fixture.componentInstance;

        expect(component.colourOf('NOT_COVERED')).not.toBe(component.colourOf('NO_FINDING'));
        expect(component.colourOf('NOT_MEASURED')).not.toBe(component.colourOf('NO_FINDING'));
    });

    it("n'affiche un compte que là où quelque chose a été compté", () => {
        // Un « 0 » en face d'une catégorie que rien ne regarde est le chiffre que toute cette
        // grille existe pour ne pas écrire.
        const cells = fixture.nativeElement.querySelectorAll('tbody tr td:nth-child(3)');
        expect([...cells].map((cell: HTMLElement) => cell.textContent!.trim()))
            .toEqual(['—', '3', '—', '—']);
    });

    it("garde l'ordre du serveur, qui est celui du standard", () => {
        expect(fixture.componentInstance.lines().map((l) => l.id)).toEqual(['A01', 'A05', 'A06', 'A07']);
    });

    it('se tait quand la grille ne peut pas être lue', async () => {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [OwaspGridComponent],
            providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();
        const failed = TestBed.createComponent(OwaspGridComponent);
        const client = TestBed.inject(HttpTestingController);
        failed.detectChanges();
        client.expectOne((call) => call.url === '/api/v1/owasp/coverage').error(new ProgressEvent('failed'));
        failed.detectChanges();

        // Le rapport en dessous porte ses propres erreurs ; une grille vide vaut mieux qu'un
        // bandeau rouge au-dessus de données valides.
        expect(failed.nativeElement.textContent.trim()).toBe('');
    });

    /**
     * <b>Une case grise sans déclaration est un aveu que personne ne revoit.</b>
     *
     * <p>Deux catégories du Top 10 ne sont atteignables par aucune analyse statique — la conception
     * non sûre ne se lit pas dans du code, et l'absence de journal ne laisse par définition aucune
     * trace. Le dire est honnête ; le laisser là indéfiniment ne l'est plus. La déclaration porte
     * un nom, une preuve et une échéance, et c'est ce que cette ligne affiche.
     */
    it('affiche ce que l\'organisation déclare d\'une catégorie que rien ne mesure', () => {
        // Les libellés viennent du paquet : affirmer sur des clés non résolues prouverait que
        // `t()` a été appelé et rien sur ce qu'un lecteur voit.
        TestBed.inject(I18nService).translations.set({
            owasp_grid: {
                declared: { APPLICABLE: 'Declared applicable' },
                implementation: { PARTIALLY_IMPLEMENTED: 'partially in place' },
                evidence: 'Evidence:',
                reviewed: 'Reviewed',
                due: 'next'
            }
        });

        // Typée d'abord, vérifiée ensuite : l'annotation donne aux littéraux les unions étroites
        // du client, et `asSchema` confronte la même valeur au document.
        const declared: OwaspGrid = {
                lines: [
                {
                    id: 'A04',
                        title: 'Insecure Design',
                        state: 'NOT_COVERED',
                        findings: 0,
                        because: 'No scanner in this deployment produces a finding in this category.',
                        declaration: {
                            framework: 'OWASP_2021',
                            controlId: 'A04',
                            applicability: 'APPLICABLE',
                            implementation: 'PARTIALLY_IMPLEMENTED',
                            justification: 'Revue de conception à chaque évolution majeure.',
                            evidenceSource: 'EXTERNAL',
                            externalEvidence: 'Comptes rendus de revue, dossier QUAL-2026',
                            owner: 'c.moreau',
                            decidedBy: 'c.moreau',
                            decidedAt: '2026-09-01T00:00:00Z',
                            reviewedAt: '2026-09-01T00:00:00Z',
                            reviewDueAt: '2027-03-01T00:00:00Z'
                        }
                    }
                ],
            covered: 0,
            withFindings: 0,
            unmeasured: 0
        };
        asSchema('DeclaredGrid', declared);

        fixture.componentInstance.grid.set(declared);
        fixture.detectChanges();

        const text = fixture.nativeElement.textContent as string;
        expect(text).toContain('Declared applicable');
        expect(text).toContain('partially in place');
        expect(text).toContain('c.moreau');
        expect(text).toContain('QUAL-2026');
    });
});
