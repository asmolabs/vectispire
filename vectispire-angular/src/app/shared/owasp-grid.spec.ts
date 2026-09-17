import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { OwaspGridComponent } from './owasp-grid';
import type { OwaspGrid } from '@/app/core/api.models';
import { I18nService } from '@/app/core/i18n/i18n.service';
import { SessionStore } from '@/app/core/session.store';
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

    /**
     * Le formulaire de déclaration, et les deux endroits où il refuse.
     *
     * <p>Ce sont les refus du serveur, dits par un bouton éteint plutôt qu'après la frappe — et ce
     * sont ceux d'ISO 27001, qui ne parlent d'aucun référentiel : une exclusion sans motif est une
     * ligne qui sort du périmètre sans dire pourquoi, une preuve déclarée ailleurs sans dire où est
     * la même omission déplacée.
     */
    describe('la déclaration', () => {
        function asSecurityLead(): void {
            TestBed.inject(SessionStore).open('a-token', {
                username: 'c.moreau',
                displayName: null,
                role: 'CISO',
                mustChangePassword: false,
                mfaEnabled: false
            });
        }

        it("ne s'offre que là où rien ne mesure", () => {
            asSecurityLead();
            const component = fixture.componentInstance;

            // A05 porte des constats : une déclaration posée à côté d'une mesure est une seconde
            // source, et c'est la mesure qui perdrait.
            expect(component.declarable(component.lines()[1])).toBe(false);
            expect(component.declarable(component.lines()[0])).toBe(true);
        });

        it("ne s'offre pas à qui ne peut pas l'écrire", () => {
            // Le serveur refuse, et un bouton qui répond 403 dit que le produit est cassé plutôt
            // que que l'action n'est pas la sienne.
            expect(fixture.componentInstance.declarable(fixture.componentInstance.lines()[0])).toBe(false);
        });

        it('refuse une exclusion sans motif, et une preuve externe sans adresse', () => {
            asSecurityLead();
            const component = fixture.componentInstance;
            component.openDeclare(component.lines()[0]);

            component.applicability = 'EXCLUDED';
            component.justification = '';
            expect(component.incomplete()).toBe(true);

            component.justification = 'Traitée par la revue de conception.';
            expect(component.incomplete()).toBe(false);

            component.applicability = 'APPLICABLE';
            component.evidenceSource = 'EXTERNAL';
            component.externalEvidence = '';
            expect(component.incomplete()).toBe(true);

            component.externalEvidence = 'Dossier QUAL-2026';
            expect(component.incomplete()).toBe(false);
        });

        /**
         * <b>`EXTERNAL` par défaut, et non `VECTISPIRE`.</b> La catégorie déclarée est celle que ce
         * produit ne mesure pas : proposer sa propre preuve par défaut inviterait à cocher la seule
         * réponse que la case contredit.
         */
        it('propose une preuve externe par défaut, puisque ce produit ne la détient pas', () => {
            asSecurityLead();
            const component = fixture.componentInstance;

            component.openDeclare(component.lines()[0]);

            expect(component.evidenceSource).toBe('EXTERNAL');
        });

        it('envoie la déclaration sur la catégorie de la ligne, et recharge la grille', () => {
            asSecurityLead();
            const component = fixture.componentInstance;
            component.openDeclare(component.lines()[0]);
            component.justification = 'Revue de conception à chaque évolution majeure.';
            component.externalEvidence = 'Dossier QUAL-2026';
            component.owner = 'c.moreau';

            component.submit();

            const sent = http.expectOne({ method: 'PUT', url: '/api/v1/owasp/coverage/A01/declaration' });
            expect(sent.request.body.applicability).toBe('APPLICABLE');
            expect(sent.request.body.evidence_source).toBe('EXTERNAL');
            expect(sent.request.body.external_evidence).toBe('Dossier QUAL-2026');
            sent.flush({});

            // Rechargée plutôt que fusionnée sur place : la grille porte des compteurs, et les
            // recalculer dans le navigateur en ferait une seconde implémentation.
            http.expectOne((call) => call.url === '/api/v1/owasp/coverage').flush(GRID);
            expect(component.editing()).toBeNull();
        });
    });
});
