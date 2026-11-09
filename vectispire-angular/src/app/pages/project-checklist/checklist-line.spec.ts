import { TestBed } from '@angular/core/testing';
import { afterEach, describe, expect, it } from 'vitest';
import { CARRIED_LINE, CHECKLIST, LINE_HISTORY, OPEN_LINE } from '@/app/core/testing/checklists.fixtures';
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
});
