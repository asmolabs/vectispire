import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { RemediationDelays } from './remediation-delays';
import { asSchema } from '@/app/core/testing/contract';

/**
 * Les délais, et le pourcentage que l'écran refuse d'afficher.
 *
 * **Une gravité sans délai fixé n'a rien à tenir.** Une barre à zéro pour cent en face d'elle
 * se lirait « on ne tient jamais les délais sur les faibles » alors que la phrase vraie est
 * « personne n'a fixé de délai pour les faibles » — et c'est le chiffre qui serait cité en
 * réunion.
 */
describe('les délais de correction', () => {
    let fixture: ComponentFixture<RemediationDelays>;
    let http: HttpTestingController;

    /**
     * **Les sévérités arrivent en majuscules sur cette route, et sur elle seule.** Le record rend
     * l'énumération Java telle quelle là où les autres routes passent par `wireName()` — le
     * backlog envoie `critical`, celle-ci envoie `CRITICAL`. L'écran n'en compare aucune à un
     * littéral, donc rien ne casse ; la fixture, elle, doit dire ce qui arrive vraiment.
     */
    const DISTRIBUTION = asSchema('RemediationDistribution', {
            windowDays: 90,
            oldestOpenDays: 241,
            oldestOpenSeverity: 'CRITICAL',
            bySeverity: [
                {
                    severity: 'CRITICAL', windowDays: 7, withinSla: 17, late: 11,
                    percentageWithinSla: 61, medianDays: 4.5, ninetiethDays: 38, openOverdue: 5, oldestOpenDays: 241
                },
                {
                    severity: 'HIGH', windowDays: 30, withinSla: 141, late: 19,
                    percentageWithinSla: 88, medianDays: 6, ninetiethDays: 52, openOverdue: 12, oldestOpenDays: 118
                },
                {
                    severity: 'LOW', windowDays: 0, withinSla: 0, late: 0,
                    percentageWithinSla: null, medianDays: 21, ninetiethDays: 147, openOverdue: 0, oldestOpenDays: 312
                }
            ]
    });

    beforeEach(async () => {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [RemediationDelays],
            providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        fixture = TestBed.createComponent(RemediationDelays);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
        http.expectOne((call) => call.url === '/api/v1/remediation/distribution').flush(DISTRIBUTION);
    }, 20_000);

    it('ne prétend pas mesurer une gravité sans délai fixé', () => {
        const component = fixture.componentInstance;
        // `LOW`, et non `low` : ce test cherchait la ligne en minuscules, donc il n'en trouvait
        // aucune et le `!` la rendait `undefined` — `hasDeadline(undefined)` levait, et ne levait
        // pas seulement parce que la fixture était fausse de la même façon. Deux erreurs qui
        // s'accordent font un test vert.
        const low = component.rows().find((row) => row.severity === 'LOW')!;

        expect(component.hasDeadline(low)).toBe(false);
    });

    it('mesure celles qui en ont un', () => {
        const component = fixture.componentInstance;

        expect(component.hasDeadline(component.rows()[0])).toBe(true);
    });

    it('passe la barre au rouge sous les trois quarts, à l’ambre sous quatre-vingt-dix', () => {
        const component = fixture.componentInstance;
        const [critical, high] = component.rows();

        expect(component.barColour(critical)).toBe('#b91c1c');
        expect(component.barColour(high)).toBe('#d97706');
    });
});
