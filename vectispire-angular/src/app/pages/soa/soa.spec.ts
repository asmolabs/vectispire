import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { Soa } from './soa';

/**
 * La déclaration d'applicabilité, et l'ordre dans lequel elle s'ouvre.
 *
 * **Le serveur rend les lignes dans l'ordre du standard, qui est le bon pour imprimer le
 * document et le mauvais pour l'ouvrir.** La question posée devant cet écran est « qu'est-ce
 * qui ne va pas », et elle se répond en haut. Un contrôle contredit rangé en douzième position
 * parce que son identifiant commence par un huit est un constat que personne ne voit.
 *
 * Le second cas verrouille les deux refus que le serveur oppose, dits ici par un bouton éteint
 * plutôt que par un message après la frappe.
 */
describe("la déclaration d'applicabilité", () => {
    let fixture: ComponentFixture<Soa>;
    let http: HttpTestingController;

    function line(id: string, divergence: string, declared: boolean) {
        return {
            control: { id, name: id, requirement: '', category: 'GOVERNANCE' },
            declaration: declared
                ? {
                      framework: 'ISO_27001', controlId: id, applicability: 'APPLICABLE',
                      justification: 'In scope.', implementation: 'IMPLEMENTED', evidenceSource: 'VECTISPIRE',
                      externalEvidence: null, owner: 'n.faure', decidedBy: 'c.moreau',
                      decidedAt: '2026-01-01T00:00:00Z', reviewedAt: '2026-01-01T00:00:00Z', reviewDueAt: null
                  }
                : null,
            measured: 'NON_COMPLIANT',
            divergence,
            reviewOverdue: false
        };
    }

    const STATEMENT = {
        framework: 'ISO_27001',
        total: 4,
        declared: 3,
        findings: 2,
        reviewsOverdue: 0,
        complete: false,
        lines: [
            line('ISO-A.5.15', 'CONSISTENT', true),
            line('ISO-A.8.9', 'UNDECLARED', false),
            line('ISO-A.8.28', 'OVERSTATED', true),
            line('ISO-A.8.8', 'CONTRADICTED', true)
        ]
    };

    beforeEach(async () => {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [Soa],
            providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        fixture = TestBed.createComponent(Soa);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
        http.expectOne((call) => call.url === '/api/v1/compliance/soa').flush([STATEMENT]);
    }, 20_000);

    it('ouvre sur les écarts, du plus grave au moins grave', () => {
        expect(fixture.componentInstance.lines().map((l) => l.control.id))
            .toEqual(['ISO-A.8.8', 'ISO-A.8.9', 'ISO-A.8.28', 'ISO-A.5.15']);
    });

    it('ne compte comme constat que ce qu’une évaluation relève', () => {
        const component = fixture.componentInstance;
        const [contradicted, undeclared, overstated, consistent] = component.lines();

        expect(component.isFinding(contradicted)).toBe(true);
        expect(component.isFinding(undeclared)).toBe(true);
        // Un document en avance sur la pratique n'est pas la même classe de problème
        // qu'une affirmation fausse.
        expect(component.isFinding(overstated)).toBe(false);
        expect(component.isFinding(consistent)).toBe(false);
    });

    it('refuse une exclusion sans justification, avant la requête', () => {
        const component = fixture.componentInstance;
        component.openDeclare(component.lines()[0]);
        component.applicability = 'EXCLUDED';
        component.justification = '   ';

        expect(component.incomplete()).toBe(true);

        component.submit();
        http.expectNone((call) => call.method === 'PUT');
    });

    it('refuse une preuve déclarée ailleurs qui ne nomme nulle part', () => {
        const component = fixture.componentInstance;
        component.openDeclare(component.lines()[0]);
        component.applicability = 'APPLICABLE';
        component.evidenceSource = 'EXTERNAL';
        component.externalEvidence = '';

        expect(component.incomplete()).toBe(true);
    });

    it('envoie la déclaration et relit le document plutôt que de recalculer l’écart', () => {
        const component = fixture.componentInstance;
        component.openDeclare(component.lines()[0]);
        component.submit();

        const call = http.expectOne('/api/v1/compliance/soa/ISO_27001/ISO-A.8.8');
        expect(call.request.method).toBe('PUT');
        expect(call.request.body.applicability).toBe('APPLICABLE');
        call.flush({});

        // Recalculer la divergence dans le navigateur en ferait une seconde implémentation
        // de la règle, qui finirait par ne plus dire la même chose que le bundle de preuves.
        http.expectOne((request) => request.url === '/api/v1/compliance/soa').flush([STATEMENT]);
    });
});
