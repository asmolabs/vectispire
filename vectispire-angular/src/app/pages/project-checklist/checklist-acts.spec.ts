import { TestBed } from '@angular/core/testing';
import { afterEach, describe, expect, it } from 'vitest';
import { CHECKLIST, OFFERED, READY_CHECKLIST, SUBMITTED_CHECKLIST } from '@/app/core/testing/checklists.fixtures';
import { BASE, buttonIn, mountOnPage, textOf } from './checklist-page.testing';
import { ChecklistActs } from './checklist-acts';

/**
 * The acts of the newest revision, on its own: a draft is submitted only when ready, a submitted one is
 * returned with a reason the form requires, and the sign-off says why it is greyed out.
 */
describe('the acts on a project checklist', () => {
    afterEach(() => TestBed.resetTestingModule());

    it('greys the submission out on a draft that is not ready, naming the lines', () => {
        const { dom } = mountOnPage(ChecklistActs, { view: CHECKLIST, offered: OFFERED });
        expect(buttonIn(dom(), 'submit-checklist').disabled).toBe(true);
        expect(textOf(dom(), '[data-testid="submit-blocked"]')).toBe(
            'Not ready to submit: lines 2, 3 still need attention.'
        );
    });

    it('submits a ready draft naming its edition', () => {
        const { dom, fixture, http } = mountOnPage(ChecklistActs, { view: READY_CHECKLIST });
        buttonIn(dom(), 'submit-checklist').click();
        fixture.detectChanges();
        const sent = http.expectOne(`${BASE}/2/submission`);
        expect(sent.request.body).toEqual({ edition: READY_CHECKLIST.checklist.edition });
    });

    it('requires a reason to return a submitted revision, says so on the field, then returns it', () => {
        const { dom, fixture, http, page } = mountOnPage(ChecklistActs, {
            view: SUBMITTED_CHECKLIST,
            role: 'ADMIN',
            username: 'bob'
        });
        buttonIn(dom(), 'return-checklist').click();
        fixture.detectChanges();
        const reason = () => dom().querySelector<HTMLTextAreaElement>('#return-reason')!;
        expect(dom().querySelector('form[data-testid="return-form"]')).not.toBeNull();
        expect(reason().required).toBe(true);

        buttonIn(dom(), 'confirm-return').click();
        fixture.detectChanges();
        expect(textOf(dom(), '[data-testid="return-error"]')).toBe(
            'Say why the checklist is returned: its authors read the reason.'
        );
        expect(reason().getAttribute('aria-invalid')).toBe('true');
        http.expectNone(`${BASE}/2/return`);

        reason().value = 'Line 3 needs its plan.';
        reason().dispatchEvent(new Event('input'));
        fixture.detectChanges();
        buttonIn(dom(), 'confirm-return').click();
        const sent = http.expectOne(`${BASE}/2/return`);
        expect(sent.request.body).toEqual({
            reason: 'Line 3 needs its plan.',
            edition: SUBMITTED_CHECKLIST.checklist.edition
        });
        sent.flush(CHECKLIST);
        fixture.detectChanges();
        expect(page.returning()).toBe(false);
        expect(page.notice()).toBe('Revision 2 returned to its authors, a draft again.');
    });

    it('greys the sign-off out for an author under four-eyes, and says why', () => {
        const { dom } = mountOnPage(ChecklistActs, { view: SUBMITTED_CHECKLIST, role: 'ADMIN', username: 'Carol' });
        expect(buttonIn(dom(), 'sign-off-checklist').disabled).toBe(true);
        expect(textOf(dom(), '[data-testid="sign-off-blocked"]')).toBe(
            'Four-eyes approval is on and you wrote part of this revision: a second person must sign it off.'
        );
    });

    it('offers to move to every published version but the one the checklist is on', () => {
        const { dom } = mountOnPage(ChecklistActs, { view: CHECKLIST, offered: OFFERED });
        const options = Array.from(dom().querySelectorAll<HTMLOptionElement>('#move-version option')).map((o) =>
            o.textContent?.trim()
        );
        expect(options).toEqual(['—', expect.stringContaining('version 2')]);
    });
});
