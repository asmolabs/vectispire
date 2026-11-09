import { TestBed } from '@angular/core/testing';
import { afterEach, describe, expect, it } from 'vitest';
import type { ChecklistView } from '@/app/core/api.models';
import { CHECKLIST, OPEN_LINE } from '@/app/core/testing/checklists.fixtures';
import { BASE, buttonIn, mountOnPage, textOf } from './checklist-page.testing';
import { LineAnswerForm } from './line-answer-form';

/**
 * The answer form of one line, on its own: what each field says it needs, the two refusals it makes
 * before sending — no value, a no without its comment — and the request it sends, from a submit.
 */
describe('the answer form of a checklist line', () => {
    afterEach(() => TestBed.resetTestingModule());

    function open(view: ChecklistView = CHECKLIST) {
        const mounted = mountOnPage(LineAnswerForm, { view }, { line: OPEN_LINE });
        mounted.page.startAnswer(OPEN_LINE);
        mounted.fixture.detectChanges();
        return mounted;
    }

    const radios = (dom: HTMLElement) =>
        Array.from(dom.querySelectorAll<HTMLInputElement>(`input[type="radio"][name="answer-${OPEN_LINE.itemId}"]`));

    it('is a form whose answer is required, each value beside the template word the document will write', () => {
        const { dom } = open();
        expect(dom().querySelector('form')).not.toBeNull();
        expect(radios(dom()).every((radio) => radio.required)).toBe(true);
        expect(textOf(dom(), `label[for="answer-${OPEN_LINE.itemId}-no"]`)).toBe('No (Non)');
    });

    it('offers not applicable only on a version whose importer mapped a word to it', () => {
        const { dom } = open({ ...CHECKLIST, offersNotApplicable: false });
        expect(radios(dom()).map((radio) => radio.id)).toEqual([
            `answer-${OPEN_LINE.itemId}-yes`,
            `answer-${OPEN_LINE.itemId}-no`
        ]);
    });

    it('requires the comment once the answer is not yes, and says so on the field when it is missing', () => {
        const { dom, fixture, http } = open();
        const comment = () => dom().querySelector<HTMLTextAreaElement>(`#comment-${OPEN_LINE.itemId}`)!;
        expect(comment().required).toBe(false);

        dom().querySelector<HTMLInputElement>(`#answer-${OPEN_LINE.itemId}-no`)!.click();
        fixture.detectChanges();
        expect(comment().required).toBe(true);

        buttonIn(dom(), `save-answer-${OPEN_LINE.itemId}`).click();
        fixture.detectChanges();
        expect(textOf(dom(), '[data-testid="answer-error"]')).toBe(
            'A no or not applicable answer needs a comment saying why.'
        );
        expect(comment().getAttribute('aria-invalid')).toBe('true');
        expect(comment().getAttribute('aria-describedby')).toBe(`answer-error-${OPEN_LINE.itemId}`);
        http.expectNone(`${BASE}/2/items/${OPEN_LINE.itemId}/answers`);
    });

    it('refuses a submit with no answer chosen, then sends the answer with its comment and the edition', () => {
        const { dom, fixture, http, page } = open();
        buttonIn(dom(), `save-answer-${OPEN_LINE.itemId}`).click();
        fixture.detectChanges();
        expect(textOf(dom(), '[data-testid="answer-error"]')).toBe('Choose an answer.');

        dom().querySelector<HTMLInputElement>(`#answer-${OPEN_LINE.itemId}-no`)!.click();
        const comment = dom().querySelector<HTMLTextAreaElement>(`#comment-${OPEN_LINE.itemId}`)!;
        comment.value = ' Two criticals, fix planned. ';
        comment.dispatchEvent(new Event('input'));
        fixture.detectChanges();
        dom().querySelector('form')!.dispatchEvent(new Event('submit'));

        const sent = http.expectOne(`${BASE}/2/items/${OPEN_LINE.itemId}/answers`);
        expect(sent.request.body).toEqual({
            value: 'no',
            comment: 'Two criticals, fix planned.',
            edition: CHECKLIST.checklist.edition
        });
        sent.flush(CHECKLIST);
        expect(page.answering()).toBeNull();
    });
});
