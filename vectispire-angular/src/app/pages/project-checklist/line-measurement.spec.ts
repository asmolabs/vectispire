import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import type { ChecklistMeasurement, MeasuredLine } from '@/app/core/api.models';
import {
    FAIL_MEASUREMENT,
    MEASURED_OPEN_LINE,
    measuredLine,
    NO_DATA_MEASUREMENT,
    SECRETS_RULE
} from '@/app/core/testing/checklists.fixtures';
import { useEnglish, useFrench } from '@/app/core/testing/english';
import { LineMeasurement } from './line-measurement';

/**
 * One line's measurement on its own, for what the checklist page's suite (`measurements.spec.ts`,
 * which reads it through the page and its requests) leaves aside: which states offer the one click,
 * a problem the line already names not badged twice, and a value this client does not know shown as
 * sent rather than as a key path (decision 0019). Nothing is sent from here: the click goes to the
 * page, which sends the answer.
 */
describe('the measurement of a checklist line', () => {
    let fixture: ComponentFixture<LineMeasurement>;
    let clicks: number;

    beforeEach(async () => {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [LineMeasurement],
            providers: [provideRouter([])]
        }).compileComponents();
        useEnglish();
    });

    function render(
        measured: MeasuredLine | null,
        options: { live?: boolean; answerable?: boolean; lineProblems?: string[] } = {}
    ): HTMLElement {
        fixture = TestBed.createComponent(LineMeasurement);
        fixture.componentRef.setInput('rule', SECRETS_RULE);
        fixture.componentRef.setInput('position', 3);
        fixture.componentRef.setInput('measured', measured);
        fixture.componentRef.setInput('live', options.live ?? true);
        fixture.componentRef.setInput('answerable', options.answerable ?? true);
        fixture.componentRef.setInput('lineProblems', options.lineProblems ?? []);
        clicks = 0;
        fixture.componentInstance.answerAsMeasured.subscribe(() => clicks++);
        fixture.detectChanges();
        return fixture.nativeElement as HTMLElement;
    }

    const failing = (extra: Partial<MeasuredLine> = {}) => measuredLine(MEASURED_OPEN_LINE, FAIL_MEASUREMENT, extra);
    const text = (page: HTMLElement, selector: string): string[] =>
        [...page.querySelectorAll(selector)].map((found) => found.textContent.replace(/\s+/g, ' ').trim());
    const named = (page: HTMLElement, name: string): HTMLButtonElement | undefined =>
        [...page.querySelectorAll('button')].find((button) => button.getAttribute('aria-label') === name);

    it('offers a no as measured on a line not met, by a button that names its line, and hands the click to the page', () => {
        const page = render(failing());

        expect(text(page, '[data-testid="outcome"]')).toEqual(['Not met']);
        const answer = named(page, 'Answer line 3 as measured');
        expect(answer?.textContent.trim()).toBe('Answer no, as measured');

        answer!.click();
        expect(clicks).toBe(1);
    });

    it('offers no answer on a frozen measurement, nor to someone who may not answer, and none where there is no data', () => {
        expect(named(render(failing(), { live: false }), 'Answer line 3 as measured')).toBeUndefined();
        expect(named(render(failing(), { answerable: false }), 'Answer line 3 as measured')).toBeUndefined();

        const noData = render(measuredLine(MEASURED_OPEN_LINE, NO_DATA_MEASUREMENT));
        expect(named(noData, 'Answer line 3 as measured')).toBeUndefined();
        expect(noData.querySelector('[data-testid="no-one-click"]')).not.toBeNull();
    });

    it('badges only the problems the line itself does not already name', () => {
        const page = render(failing({ problems: ['measurement_contradicted', 'evidence_required'] }), {
            lineProblems: ['measurement_contradicted']
        });

        expect(text(page, '[data-testid="measured-problem"]')).toEqual(['No data: a yes needs a proof']);
    });

    it('says when nothing was stored for the revision, rather than nothing', () => {
        const page = render(failing({ measurement: null, reconciliation: 'not_measured_here' }));

        expect(text(page, '[data-testid="measurement-none"]')).toEqual([
            'No measurement was stored for this revision.'
        ]);
        expect(page.querySelector('[data-testid="outcome"]')).toBeNull();
    });

    it('shows a value this client does not know as the server sent it, never as a key', () => {
        // A newer server's words, which today's document does not hold: built past `asSchema` on purpose.
        const found = {
            ...FAIL_MEASUREMENT,
            outcome: 'partial',
            evidence: {
                ...FAIL_MEASUREMENT.evidence,
                repositories: [{ ...FAIL_MEASUREMENT.evidence.repositories[0], source: 'sbom_import', sourceId: 9 }]
            }
        } as unknown as ChecklistMeasurement;
        const page = render({
            ...failing(),
            measurement: found,
            reconciliation: 'disputed'
        } as unknown as MeasuredLine);
        named(page, 'Evidence measured for line 3')!.click();
        fixture.detectChanges();

        expect(text(page, '[data-testid="outcome"]')).toEqual(['partial']);
        expect(text(page, '[data-testid="reconciliation"]')).toEqual(['disputed']);
        expect(text(page, '[data-testid="measured-evidence-3"] tbody td:nth-child(4)')).toEqual(['sbom_import']);
        expect(page.textContent).not.toMatch(/project_checklist\./);
    });

    it('speaks French to a French reader, its buttons named in French', () => {
        const page = render(failing());
        useFrench();
        fixture.detectChanges();

        expect(text(page, '[data-testid="outcome"]')).toEqual(['Non atteint']);
        expect(named(page, 'Répondre à la ligne 3 comme mesuré')?.textContent.trim()).toBe(
            'Répondre non, comme mesuré'
        );
        expect(named(page, 'Preuves mesurées pour la ligne 3')?.textContent.trim()).toBe('Afficher les preuves (1)');
    });
});
