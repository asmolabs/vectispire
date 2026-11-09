import { TestBed } from '@angular/core/testing';
import { afterEach, describe, expect, it } from 'vitest';
import type { ChecklistOfferedVersion } from '@/app/core/api.models';
import { CHECKLIST, OFFERED } from '@/app/core/testing/checklists.fixtures';
import { BASE, buttonIn, mountOnPage, textOf } from './checklist-page.testing';
import { ChecklistOpening } from './checklist-opening';

/**
 * The card a project without a checklist shows, on its own: a reader is told there is none, a writer
 * offered the published versions — one no sign-off could fill in disabled and saying why — and the
 * opening names no edition, since the context saw no checklist.
 */
describe('opening a project checklist', () => {
    afterEach(() => TestBed.resetTestingModule());

    const UNRENDERABLE: ChecklistOfferedVersion = {
        ...OFFERED[1],
        unrenderable: { cells: [], detail: 'The workbook has no sheet named Checklist.' }
    };

    it('tells a reader there is none, and offers nothing', () => {
        const { dom } = mountOnPage(ChecklistOpening, { role: 'AUDITOR', offered: OFFERED });
        expect(textOf(dom(), '[data-testid="no-checklist"]')).toBe(
            'This project has no security checklist yet. Somebody with write access opens one on a published template version.'
        );
        expect(dom().querySelector('#open-version')).toBeNull();
    });

    it('lists a version no sign-off could fill in as disabled, with the server words why', () => {
        const { dom } = mountOnPage(ChecklistOpening, { offered: [OFFERED[0], UNRENDERABLE] });
        const options = Array.from(dom().querySelectorAll<HTMLOptionElement>('#open-version option'));
        expect(options.map((option) => option.disabled)).toEqual([false, false, true]);
        expect(textOf(dom(), '[data-testid="open-unrenderable"]')).toContain(
            'The workbook has no sheet named Checklist.'
        );
    });

    it('opens the chosen version naming no edition, and says so', () => {
        const { dom, fixture, http, page } = mountOnPage(ChecklistOpening, { offered: OFFERED });
        const select = dom().querySelector<HTMLSelectElement>('#open-version')!;
        select.selectedIndex = 1;
        select.dispatchEvent(new Event('change'));
        fixture.detectChanges();
        buttonIn(dom(), 'open-checklist').click();

        const sent = http.expectOne({ method: 'POST', url: BASE });
        expect(sent.request.body).toEqual({ template: 'release', version: 1 });
        sent.flush(CHECKLIST);
        http.expectOne({ method: 'GET', url: BASE });
        expect(page.notice()).toBe('The checklist is open: revision 2.');
    });
});
