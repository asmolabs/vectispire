import { TestBed } from '@angular/core/testing';
import { afterEach, describe, expect, it } from 'vitest';
import type { ChecklistLine, MeasuredLine } from '@/app/core/api.models';
import {
    CARRIED_LINE,
    CHECKLIST,
    FAIL_MEASUREMENT,
    LINE_HISTORY,
    MEASURED_OPEN_LINE,
    MEASUREMENTS,
    measuredLine,
    NO_DATA_MEASUREMENT,
    OPEN_LINE,
    READY_LINE
} from '@/app/core/testing/checklists.fixtures';
import { useFrench } from '@/app/core/testing/english';
import { BASE, buttonIn, mountOnPage, textOf } from './checklist-page.testing';
import { ChecklistLineCard } from './checklist-line';

/**
 * One line of the checklist, on its own: its problems in words, a carried answer standing out with its
 * confirmation, what the last refusal said of it, and its history read on request — each read from
 * the line and the page's state, and following a switch of language.
 */
describe('a line of a project checklist', () => {
    afterEach(() => TestBed.resetTestingModule());

    it('names its problems, and stands out with the confirmation a carried answer awaits', () => {
        const { dom, fixture, http } = mountOnPage(ChecklistLineCard, { view: CHECKLIST }, { line: CARRIED_LINE });
        expect(textOf(dom(), '[data-testid="problems"]')).toBe('Awaiting confirmation');
        expect(dom().querySelector('[data-testid="awaiting-2"]')).not.toBeNull();

        buttonIn(dom(), 'Confirm the answer to line 2').click();
        fixture.detectChanges();
        const sent = http.expectOne(`${BASE}/2/items/${CARRIED_LINE.itemId}/confirmation`);
        expect(sent.request.body).toEqual({ edition: CHECKLIST.checklist.edition });
    });

    it('shows what the last refusal kept the line back for, and the refusal itself on the line', () => {
        const { dom, fixture, page } = mountOnPage(ChecklistLineCard, { view: CHECKLIST }, { line: OPEN_LINE });
        page.incomplete.set({ [OPEN_LINE.itemId]: ['comment_required'] });
        page.refusal.set({ message: 'Line 3 changed meanwhile.', reload: true, itemId: OPEN_LINE.itemId });
        fixture.detectChanges();
        expect(textOf(dom(), '[data-testid="incomplete-3"] p-tag')).toBe('Comment required');
        expect(textOf(dom(), '[data-testid="refusal-message"]')).toBe('Line 3 changed meanwhile.');

        page.refusal.set({ message: 'Another line.', reload: false, itemId: CARRIED_LINE.itemId });
        fixture.detectChanges();
        expect(dom().querySelector('[data-testid="refusal"]')).toBeNull();
    });

    it('reads its history on request, and closes it on the second', () => {
        const { dom, fixture, http } = mountOnPage(ChecklistLineCard, { view: CHECKLIST }, { line: CARRIED_LINE });
        buttonIn(dom(), 'History of line 2').click();
        fixture.detectChanges();
        expect(textOf(dom(), '[data-testid="history-2"]')).toBe('Loading...');
        http.expectOne(`${BASE}/2/items/${CARRIED_LINE.itemId}/history`).flush(LINE_HISTORY);
        fixture.detectChanges();
        expect(dom().querySelector('[data-testid="history-row-610"]')).not.toBeNull();

        buttonIn(dom(), 'History of line 2').click();
        fixture.detectChanges();
        expect(dom().querySelector('[data-testid="history-2"]')).toBeNull();
    });

    it('opens the answer form on this line only', () => {
        const { dom, fixture, page } = mountOnPage(ChecklistLineCard, { view: CHECKLIST }, { line: OPEN_LINE });
        page.startAnswer(CARRIED_LINE);
        fixture.detectChanges();
        expect(dom().querySelector('[data-testid="answer-form-3"]')).toBeNull();

        buttonIn(dom(), 'answer-103').click();
        fixture.detectChanges();
        expect(dom().querySelector('[data-testid="answer-form-3"]')).not.toBeNull();
    });

    it('rewrites its problems when the language changes', () => {
        const { dom, fixture } = mountOnPage(ChecklistLineCard, { view: CHECKLIST }, { line: OPEN_LINE });
        expect(textOf(dom(), '[data-testid="problems"]')).toBe('Not answered yet');
        useFrench();
        fixture.detectChanges();
        expect(textOf(dom(), '[data-testid="problems"]')).toBe('Pas encore de réponse');
    });

    // -------------------------------------------------------- an automatic answer whose measurement lapsed

    /**
     * Line 3 answered no by Vectispire on 11 September from a failing measurement, read today with no data
     * — its newest evidence older than the rule allows. The server reconciles that as
     * `declared_not_measured`, and the line used to say "Declared, not measured" beside "Automatic —
     * measured by Vectispire": a person's declaration and a current measurement, neither of which was
     * true. The answer is dated and the badge says the measurement lapsed.
     */
    const answered = (kind: 'system' | 'person'): ChecklistLine => ({
        ...MEASURED_OPEN_LINE,
        problems: [],
        answer: {
            ...READY_LINE.answer!,
            id: 703,
            itemId: MEASURED_OPEN_LINE.itemId,
            value: 'no',
            answeredBy: kind === 'system' ? 'Vectispire' : 'erin',
            answeredByKind: kind,
            answeredAt: '2026-09-11T08:00:00Z'
        }
    });
    const measuredAs = (
        line: ChecklistLine,
        found: typeof FAIL_MEASUREMENT,
        reconciliation: MeasuredLine['reconciliation']
    ) => ({
        ...MEASUREMENTS,
        lines: [measuredLine(line, found, { reconciliation })]
    });
    const mountAnswered = (
        kind: 'system' | 'person',
        found: typeof FAIL_MEASUREMENT,
        reconciliation: MeasuredLine['reconciliation']
    ) => {
        const line = answered(kind);
        return mountOnPage(
            ChecklistLineCard,
            { view: { ...CHECKLIST, lines: [line] }, measurements: measuredAs(line, found, reconciliation) },
            { line }
        );
    };

    it('dates an automatic answer whose measurement has no data now, rather than calling it declared', () => {
        const { dom } = mountAnswered('system', NO_DATA_MEASUREMENT, 'declared_not_measured');

        expect(textOf(dom(), '[data-testid="answer-automatic"]')).toBe(
            'Automatic — measured by Vectispire on 11/09/2026, no data since'
        );
        expect(textOf(dom(), '[data-testid="reconciliation"]')).toBe('Measured before, no data now');
    });

    it("keeps a person's answer without data declared, and an automatic one still measured as it was", () => {
        const person = mountAnswered('person', NO_DATA_MEASUREMENT, 'declared_not_measured').dom();
        expect(person.querySelector('[data-testid="answer-automatic"]')).toBeNull();
        expect(textOf(person, '[data-testid="reconciliation"]')).toBe('Declared, not measured');
        TestBed.resetTestingModule();

        const current = mountAnswered('system', FAIL_MEASUREMENT, 'consistent').dom();
        expect(textOf(current, '[data-testid="answer-automatic"]')).toBe('Automatic — measured by Vectispire');
        expect(textOf(current, '[data-testid="reconciliation"]')).not.toBe('Measured before, no data now');
    });

    it('words the lapsed measurement in French too', () => {
        const { dom, fixture } = mountAnswered('system', NO_DATA_MEASUREMENT, 'declared_not_measured');
        useFrench();
        fixture.detectChanges();

        expect(textOf(dom(), '[data-testid="answer-automatic"]')).toBe(
            'Automatique — mesuré par Vectispire le 11/09/2026, sans données depuis'
        );
        expect(textOf(dom(), '[data-testid="reconciliation"]')).toBe('Mesuré auparavant, sans données aujourd’hui');
    });

    /**
     * Angular drops a text node made only of whitespace, so a label in its own `<span>` followed by an
     * element ran into it on screen: "Réponse :Non", "Preuves :aucune", "Mesurée parConstats".
     */
    it('keeps a space between each label and what follows it', () => {
        const { dom } = mountAnswered('person', NO_DATA_MEASUREMENT, 'declared_not_measured');

        expect(textOf(dom(), '[data-testid="answer"]')).toMatch(/^Answer: No /);
        expect(textOf(dom(), '[data-testid="evidence"]')).toBe('Evidence: none attached.');
        expect(textOf(dom(), '[data-testid="measurement-3"]')).toMatch(/^Measured by \S/);
    });
});
