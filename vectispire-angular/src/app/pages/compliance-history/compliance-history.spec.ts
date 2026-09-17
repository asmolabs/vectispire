import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { ComplianceHistoryPage } from './compliance-history';
import { asSchema } from '@/app/core/testing/contract';

/**
 * La progression, et la couleur qu'elle refuse de donner à une baisse.
 *
 * <h2>La moitié cliente d'une règle du domaine</h2>
 *
 * <p>Le domaine attribue déjà chaque mois à sa cause : une baisse survenue alors que le parc a
 * grandi est un {@code ESTATE_GREW}, pas un {@code DECLINED}. Mais cette distinction ne sert à
 * rien si l'écran peint les deux en rouge — un lecteur regarde la couleur avant de lire la
 * colonne « pourquoi », et un graphique où surveiller plus large est rouge apprend à surveiller
 * moins.
 *
 * <p>C'est pour cela que le premier cas porte sur la couleur et non sur le texte : le texte est
 * déjà éprouvé côté domaine, la couleur ne l'est nulle part ailleurs.
 */
describe('la progression de la conformité', () => {
    let fixture: ComponentFixture<ComplianceHistoryPage>;
    let http: HttpTestingController;

    function step(period: string, score: number, movement: string, targets = 10) {
        return asSchema('Step', {
            snapshot: {
                period, framework: 'ISO_27001', score, status: 'PARTIAL',
                targets, observed: targets, fresh: targets, freshnessDays: 30,
                endOfLifeEnabled: true, codeAnalysisReaches: true,
                controlsTotal: 4, controlsDeclared: 4, soaFindings: 0,
                capturedAt: '2026-09-01T00:00:00Z'
            },
            delta: 0,
            movement,
            because: 'parce que.'
        });
    }

    async function mount(body: unknown[]) {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [ComplianceHistoryPage],
            providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        fixture = TestBed.createComponent(ComplianceHistoryPage);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
        http.expectOne((call) => call.url === '/api/v1/compliance/history').flush(body);
        fixture.detectChanges();
    }

    beforeEach(async () => {
        await mount([{
            framework: 'ISO_27001',
            comparable: false,
            steps: [step('2026-07', 90, 'FIRST', 10), step('2026-08', 71, 'ESTATE_GREW', 14)]
        }]);
    }, 20_000);

    it('ne peint pas comme une régression une baisse due à un parc plus large', () => {
        const component = fixture.componentInstance;

        expect(component.colourOf('ESTATE_GREW')).not.toBe(component.colourOf('DECLINED'));
        expect(component.colourOf('ESTATE_SHRANK')).not.toBe(component.colourOf('IMPROVED'));
        expect(component.colourOf('RULES_CHANGED')).not.toBe(component.colourOf('DECLINED'));
    });

    it("dit qu'une série au parc mouvant n'est pas une tendance", () => {
        // Sans cette mention, deux points reliés se lisent comme une trajectoire, quelle que soit
        // la distance entre les deux parcs qui les ont produits.
        expect(fixture.nativeElement.textContent).toContain('history_compliance.not_comparable');
    });

    it('ne montre aucun écart sur la première capture', () => {
        // Un « 0 » en face du premier mois se lirait « on n'a pas bougé » là où la phrase vraie
        // est « il n'y a rien à quoi se comparer ».
        const changes = fixture.nativeElement.querySelectorAll('tbody tr td:nth-child(3)');
        expect([...changes].map((c: HTMLElement) => c.textContent!.trim())).toEqual(['—', '0']);
    });

    it('échelonne la barre sur cent et non sur le maximum de la série', async () => {
        // Une échelle qui s'ajuste ferait passer une progression de deux points pour une envolée.
        const component = fixture.componentInstance;
        expect(component.height(step('2026-08', 50, 'STEADY') as never)).toBe(50);
        expect(component.height(step('2026-08', 0, 'STEADY') as never))
            .toBeGreaterThan(0);
    });

    it("annonce l'absence de capture plutôt qu'un graphique vide", async () => {
        await mount([]);

        expect(fixture.nativeElement.textContent).toContain('history_compliance.empty');
    });
});
