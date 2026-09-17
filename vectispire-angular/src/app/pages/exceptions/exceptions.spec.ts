import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { Exceptions } from './exceptions';
import { asSchema } from '@/app/core/testing/contract';

/**
 * Le registre des exceptions, et la revue qui n'existait pas.
 *
 * **Ce qui est couvert ici n'est pas l'affichage mais la seule action dont l'effet est
 * invisible.** Confirmer une exception ne change ni sa décision, ni son échéance, ni son
 * auteur : la seule chose qui bouge est la preuve que quelqu'un a regardé. Un écran qui
 * n'enverrait rien dans ce cas aurait exactement la même apparence, et c'est précisément le
 * défaut que cette fonctionnalité corrige côté serveur.
 *
 * Le second cas verrouille le refus local de prolonger sans date. Le serveur le refuse aussi ;
 * ce qui est asserté ici est que l'écran ne laisse pas partir la requête pour afficher son
 * erreur — un bouton désactivé dit la même chose sans bruit.
 */
describe('le registre des exceptions', () => {
    let fixture: ComponentFixture<Exceptions>;
    let http: HttpTestingController;

    const REGISTER = asSchema('Register', {
            entries: [
                {
                    issue_id: 41,
                    identifier: 'CVE-2026-0001',
                    severity: 'high',
                    target_kind: 'REPOSITORY',
                    target_id: 7,
                    target_name: 'paiement-api',
                    decision: 'not_affected',
                    justification: 'vulnerable_code_not_in_execute_path',
                    comment: null,
                    actor: 'c.moreau',
                    origin: 'manual',
                    decided_at: '2026-01-12T09:00:00Z',
                    expires_at: '2026-12-31T00:00:00Z',
                    lapsed: false,
                    last_reviewed_at: null,
                    last_reviewed_by: null
                }
            ],
            granted: 1,
            awaiting_approval: 0,
            lapsed: 0,
            never_reviewed: 1,
            next_cursor: null
    });

    beforeEach(async () => {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [Exceptions],
            providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        fixture = TestBed.createComponent(Exceptions);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();

        http.expectOne((call) => call.url === '/api/v1/exceptions').flush(REGISTER);
    }, 20_000);

    it('envoie une confirmation, qui ne change rien sauf la preuve', () => {
        const component = fixture.componentInstance;
        component.openReview(REGISTER.entries[0]);
        component.submitReview();

        const call = http.expectOne('/api/v1/exceptions/41/reviews');
        expect(call.request.body.outcome).toBe('CONFIRMED');
        expect(call.request.body.new_expiry).toBeNull();

        // **La ligne revient datée**, comme le serveur la renverrait : les compteurs sont dérivés
        // des lignes et non repris du serveur, si bien qu'un jeu de données où le compteur bouge
        // sans que la ligne bouge ne décrit plus rien de réel.
        call.flush({
            ...REGISTER,
            entries: [{ ...REGISTER.entries[0], last_reviewed_at: '2026-09-14T10:00:00Z', last_reviewed_by: 'n.faure' }],
            never_reviewed: 0
        });

        expect(component.neverReviewed()).toBe(0);
        expect(component.reviewing()).toBeNull();
    });

    it('ne laisse pas partir une prolongation sans date', () => {
        const component = fixture.componentInstance;
        component.openReview(REGISTER.entries[0]);
        component.outcome = 'EXTENDED';

        expect(component.incomplete()).toBe(true);

        component.submitReview();
        http.expectNone('/api/v1/exceptions/41/reviews');
    });

    it('propose la suite même quand la page ne contenait rien de visible', () => {
        // **La moitié cliente du même défaut que côté serveur.** La visibilité s'applique après la
        // lecture : une fenêtre entière peut n'appartenir qu'à d'autres. Masquer le bouton parce
        // que la page est vide ferait s'arrêter le lecteur restreint juste avant ses propres
        // lignes — et il est le seul à ne pas pouvoir s'en apercevoir.
        const component = fixture.componentInstance;
        component.load();
        http.expectOne((call) => call.url === '/api/v1/exceptions').flush({
            entries: [], granted: 0, awaiting_approval: 0, lapsed: 0, never_reviewed: 0,
            next_cursor: '1757836800000:41'
        });

        expect(component.loaded()).toHaveLength(0);
        expect(component.hasMore()).toBe(true);

        component.more();
        const next = http.expectOne((call) => call.url === '/api/v1/exceptions');
        expect(next.request.params.get('cursor')).toBe('1757836800000:41');
        next.flush({ ...REGISTER, next_cursor: null });

        expect(component.loaded()).toHaveLength(1);
        expect(component.hasMore()).toBe(false);
    });

    it('accumule les pages et recompte sur ce qui est chargé', () => {
        const component = fixture.componentInstance;
        expect(component.granted()).toBe(1);

        component.load();
        http.expectOne((call) => call.url === '/api/v1/exceptions')
            .flush({ ...REGISTER, next_cursor: '1757836800000:41' });
        component.more();
        http.expectOne((call) => call.url === '/api/v1/exceptions').flush({
            ...REGISTER,
            entries: [{ ...REGISTER.entries[0], issue_id: 42 }],
            next_cursor: null
        });

        // Les compteurs viennent des lignes chargées et non du serveur : additionner les pages
        // donnerait un total qui grandit à mesure qu'on lit, ce qui n'est le total de rien.
        expect(component.loaded()).toHaveLength(2);
        expect(component.granted()).toBe(2);
    });

    it("compte les jamais revues comme un chiffre à part des périmées", () => {
        // Les deux disent « personne ne s'en occupe » et ne sont pas la même phrase : une
        // exception périmée a eu une échéance qui est passée, une jamais revue peut être
        // parfaitement en cours et n'avoir jamais été rouverte.
        expect(fixture.componentInstance.lapsed()).toBe(0);
        expect(fixture.componentInstance.neverReviewed()).toBe(1);
    });
});
