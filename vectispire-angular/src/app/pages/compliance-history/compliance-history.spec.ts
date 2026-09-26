import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { ComplianceHistoryPage } from './compliance-history';
import { asSchema } from '@/app/core/testing/contract';

/**
 * Progress, and the colour it refuses to give a drop.
 *
 * <h2>The client half of a domain rule</h2>
 *
 * <p>The domain already attributes each month to its cause: a drop that happened while the estate
 * grew is an {@code ESTATE_GREW}, not a {@code DECLINED}. But that distinction is useless if the
 * screen paints both red — a reader looks at the colour before reading the "why" column, and a
 * chart where watching wider is red teaches people to watch less.
 *
 * <p>That is why the first case is about the colour and not about the text: the text is already
 * tested on the domain side, the colour nowhere else.
 */
describe('compliance progress', () => {
    let fixture: ComponentFixture<ComplianceHistoryPage>;
    let http: HttpTestingController;

    function step(period: string, score: number, movement: string, targets = 10) {
        return asSchema('Step', {
            snapshot: {
                period,
                framework: 'ISO_27001',
                score,
                status: 'PARTIAL',
                targets,
                observed: targets,
                fresh: targets,
                freshnessDays: 30,
                endOfLifeEnabled: true,
                codeAnalysisReaches: true,
                controlsTotal: 4,
                controlsDeclared: 4,
                soaFindings: 0,
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
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        fixture = TestBed.createComponent(ComplianceHistoryPage);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
        http.expectOne((call) => call.url === '/api/v1/compliance/history').flush(body);
        fixture.detectChanges();
    }

    beforeEach(async () => {
        await mount([
            {
                framework: 'ISO_27001',
                comparable: false,
                steps: [step('2026-07', 90, 'FIRST', 10), step('2026-08', 71, 'ESTATE_GREW', 14)]
            }
        ]);
    }, 20_000);

    it('does not paint a drop caused by a wider estate as a regression', () => {
        const component = fixture.componentInstance;

        expect(component.colourOf('ESTATE_GREW')).not.toBe(component.colourOf('DECLINED'));
        expect(component.colourOf('ESTATE_SHRANK')).not.toBe(component.colourOf('IMPROVED'));
        expect(component.colourOf('RULES_CHANGED')).not.toBe(component.colourOf('DECLINED'));
    });

    it('says a series over a moving estate is not a trend', () => {
        // Without that note, two joined points read as a trajectory, whatever the distance between
        // the two estates that produced them.
        expect(fixture.nativeElement.textContent).toContain('history_compliance.not_comparable');
    });

    it('shows no delta on the first capture', () => {
        // A "0" against the first month would read as "we did not move" where the true sentence is
        // "there is nothing to compare with".
        const changes = fixture.nativeElement.querySelectorAll('tbody tr td:nth-child(3)');
        expect([...changes].map((c: HTMLElement) => c.textContent.trim())).toEqual(['—', '0']);
    });

    it('scales the bar against one hundred and not against the series maximum', () => {
        // A scale that adjusts itself would make a two-point gain look like a leap.
        const component = fixture.componentInstance;
        expect(component.height(step('2026-08', 50, 'STEADY') as never)).toBe(50);
        expect(component.height(step('2026-08', 0, 'STEADY') as never)).toBeGreaterThan(0);
    });

    it('announces the absence of captures rather than an empty chart', async () => {
        await mount([]);

        expect(fixture.nativeElement.textContent).toContain('history_compliance.empty');
    });
});
