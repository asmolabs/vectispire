import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { Exceptions } from './exceptions';

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

    const REGISTER = {
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
        never_reviewed: 1
    };

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

        call.flush({ ...REGISTER, never_reviewed: 0 });

        expect(component.register()!.never_reviewed).toBe(0);
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

    it("compte les jamais revues comme un chiffre à part des périmées", () => {
        // Les deux disent « personne ne s'en occupe » et ne sont pas la même phrase : une
        // exception périmée a eu une échéance qui est passée, une jamais revue peut être
        // parfaitement en cours et n'avoir jamais été rouverte.
        expect(fixture.componentInstance.register()!.lapsed).toBe(0);
        expect(fixture.componentInstance.register()!.never_reviewed).toBe(1);
    });
});
