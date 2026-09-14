import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { RuleCoverageBanner } from './rule-coverage-banner';

/**
 * Le bandeau qui dit qu'une absence de constat est une absence de recherche.
 *
 * **Le cas qui compte le plus est celui où il ne s'affiche pas.** Un avertissement montré
 * quand tout va bien perd son sens en quelques jours, et alors celui qui compte devient
 * invisible aussi — c'est la raison pour laquelle `COVERED` ne rend rien, et c'est ce que le
 * premier test verrouille.
 */
describe('le bandeau de couverture des règles', () => {
    let fixture: ComponentFixture<RuleCoverageBanner>;
    let http: HttpTestingController;

    async function mount(body: Record<string, unknown> | null) {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [RuleCoverageBanner],
            providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        fixture = TestBed.createComponent(RuleCoverageBanner);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();

        const call = http.expectOne((request) => request.url === '/api/v1/rule-sets/coverage');
        if (body) {
            call.flush(body);
        } else {
            call.error(new ProgressEvent('failed'));
        }
        fixture.detectChanges();
    }

    beforeEach(async () => {
        await mount({ state: 'COVERED', languagesWithRules: ['java'], ecosystemsInEstate: ['maven'], uncovered: [], ruleFiles: 40 });
    }, 20_000);

    it('ne dit rien quand chaque écosystème du parc a des règles', () => {
        expect(fixture.componentInstance.visible()).toBe(false);
        expect(fixture.nativeElement.textContent.trim()).toBe('');
    });

    it("avertit quand seule la règle embarquée est là", async () => {
        await mount({ state: 'UNCONFIGURED', languagesWithRules: ['python'], ecosystemsInEstate: ['maven'], uncovered: ['java'], ruleFiles: 1 });

        expect(fixture.componentInstance.visible()).toBe(true);
    });

    it('nomme les écosystèmes sans règle quand la couverture est partielle', async () => {
        await mount({ state: 'PARTIAL', languagesWithRules: ['java'], ecosystemsInEstate: ['maven', 'go'], uncovered: ['go'], ruleFiles: 40 });

        expect(fixture.componentInstance.uncovered()).toEqual(['go']);
        expect(fixture.nativeElement.textContent).toContain('go');
    });

    it("se tait quand la couverture n'a pas pu être lue", async () => {
        // Un bandeau d'erreur au-dessus de données valides dirait « quelque chose ne va pas »
        // sans dire quoi. L'écran hôte porte ses propres erreurs.
        await mount(null);

        expect(fixture.componentInstance.visible()).toBe(false);
    });
});
