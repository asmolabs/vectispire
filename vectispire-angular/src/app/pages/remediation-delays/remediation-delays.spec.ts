import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { RemediationDelays } from './remediation-delays';

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

    const DISTRIBUTION = {
        windowDays: 90,
        oldestOpenDays: 241,
        oldestOpenSeverity: 'critical',
        bySeverity: [
            {
                severity: 'critical', windowDays: 7, withinSla: 17, late: 11,
                percentageWithinSla: 61, medianDays: 4.5, ninetiethDays: 38, openOverdue: 5, oldestOpenDays: 241
            },
            {
                severity: 'high', windowDays: 30, withinSla: 141, late: 19,
                percentageWithinSla: 88, medianDays: 6, ninetiethDays: 52, openOverdue: 12, oldestOpenDays: 118
            },
            {
                severity: 'low', windowDays: 0, withinSla: 0, late: 0,
                percentageWithinSla: null, medianDays: 21, ninetiethDays: 147, openOverdue: 0, oldestOpenDays: 312
            }
        ]
    };

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
        const low = component.rows().find((r) => r.severity === 'low')!;

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
