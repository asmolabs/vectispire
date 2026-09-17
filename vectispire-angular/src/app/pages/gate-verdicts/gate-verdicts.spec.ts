import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { GateVerdicts } from './gate-verdicts';
import { asSchema } from '@/app/core/testing/contract';

/**
 * Le registre des verdicts, et le chiffre qu'il ne doit pas inventer.
 *
 * **Zéro verdict ne fait pas zéro pour cent.** Sur une instance neuve, un taux de refus à
 * `0 %` se lit « la barrière ne refuse rien » alors que la phrase vraie est « la barrière n'a
 * pas encore répondu » — et c'est exactement la confusion que tout cet écran existe pour
 * empêcher.
 */
describe('le registre des verdicts', () => {
    let fixture: ComponentFixture<GateVerdicts>;
    let http: HttpTestingController;

    function row(id: string, passed: boolean) {
        return {
            id,
            target_kind: 'REPOSITORY',
            target_id: 7,
            passed,
            evaluated: passed ? 0 : 412,
            violations: passed ? 0 : 3,
            counts_by_severity: { critical: passed ? 0 : 1, high: 0, medium: 0, low: 0 },
            fail_on_severity: 'high',
            policy_source: 'TARGET',
            policy_version: 4,
            relaxations_ignored: false,
            decided_at: '2026-09-14T09:00:00Z',
            decided_by: 'ci-pipeline'
        };
    }

    async function mount(body: Record<string, unknown>) {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [GateVerdicts],
            providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        fixture = TestBed.createComponent(GateVerdicts);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
        http.expectOne((call) => call.url === '/api/v1/gate/verdicts').flush(asSchema('VerdictRegister', body));
    }

    beforeEach(async () => {
        await mount({ verdicts: [row('a', true), row('b', false)], passed: 1, refused: 1 });
    }, 20_000);

    it('ne produit pas de taux de refus quand la barrière n’a jamais répondu', async () => {
        await mount({ verdicts: [], passed: 0, refused: 0 });

        expect(fixture.componentInstance.refusalRate())
            .toBeNull();
    });

    it('calcule le taux sur le total des réponses', () => {
        expect(fixture.componentInstance.refusalRate()).toBe(50);
    });

    it('ne garde que les refus quand on le demande', () => {
        const component = fixture.componentInstance;
        expect(component.shown()).toHaveLength(2);

        component.refusalsOnly.set(true);

        expect(component.shown().map((r) => r.id)).toEqual(['b']);
    });

    it('n’affiche que les gravités qui portent un compte', () => {
        // Une ligne de gravités dont trois valent zéro se lit comme un bruit et cache la
        // quatrième, qui est la seule à dire pourquoi la barrière a refusé.
        const refusal = fixture.componentInstance.shown().find((r) => !r.passed)!;

        expect(fixture.componentInstance.counts(refusal)).toEqual([{ severity: 'critical', count: 1 }]);
    });
});
