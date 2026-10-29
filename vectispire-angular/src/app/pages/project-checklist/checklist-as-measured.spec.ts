import { TestBed } from '@angular/core/testing';
import { afterEach, describe, expect, it } from 'vitest';
import type { AsMeasuredSkipReason, ChecklistAsMeasuredSkip } from '@/app/core/api.models';
import { MEASURED_CHECKLIST, MEASUREMENTS } from '@/app/core/testing/checklists.fixtures';
import { buttonIn, mountOnPage, textOf } from './checklist-page.testing';
import { ChecklistAsMeasuredPanel } from './checklist-as-measured';

/**
 * Above the lines, on its own: whether the measurements move, and the summary of the last "every
 * measured line" act read against the view as it now is. What the act sends is the page's suite's
 * (`measurements.spec.ts`), which reads it through the routes.
 */
describe('the as-measured panel of a project checklist', () => {
    afterEach(() => TestBed.resetTestingModule());

    const skip = (itemId: number, position: number, reason: AsMeasuredSkipReason): ChecklistAsMeasuredSkip => ({
        itemId,
        position,
        reason,
        outcome: 'pass',
        noDataReason: null,
        evidenceDigest: 'a'.repeat(64),
        answer: null
    });

    it('says the measurements are being read until they are', () => {
        const { dom, fixture, page } = mountOnPage(ChecklistAsMeasuredPanel, { view: MEASURED_CHECKLIST });
        expect(dom().querySelector('[data-testid="measurements-loading"]')).not.toBeNull();

        page.measurements.set({ ...MEASUREMENTS, live: false, status: 'signed_off' });
        fixture.detectChanges();
        expect(textOf(dom(), '[data-testid="measurements-mode"]')).toBe(
            'Measurements frozen by the sign-off: the evidence as it was judged then, not recomputed over data that has moved since.'
        );
    });

    it('lists what the act left, by reason in the order a person deals with them, and only what is still owed', () => {
        const { dom, fixture, page } = mountOnPage(ChecklistAsMeasuredPanel, {
            view: MEASURED_CHECKLIST,
            measurements: MEASUREMENTS
        });
        page.asMeasured.set({
            revision: 2,
            answered: 2,
            sent: new Set([103]),
            skipped: [skip(103, 3, 'no_data'), skip(102, 2, 'already_answered'), skip(101, 1, 'needs_comment')]
        });
        fixture.detectChanges();

        expect(textOf(dom(), '[data-testid="as-measured-answered"]')).toBe('2 lines answered yes as measured.');
        // Line 1 is answered in the view since: its no is not owed any more. Line 2 was not sent.
        const groups = Array.from(dom().querySelectorAll('[data-testid^="as-measured-"]'))
            .map((group) => group.getAttribute('data-testid'))
            .filter((id) => id !== 'as-measured-summary' && id !== 'as-measured-answered');
        expect(groups).toEqual(['as-measured-no_data']);

        buttonIn(dom(), 'dismiss-as-measured').click();
        fixture.detectChanges();
        expect(dom().querySelector('[data-testid="as-measured-summary"]')).toBeNull();
    });
});
