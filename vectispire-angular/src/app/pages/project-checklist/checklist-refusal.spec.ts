import { TestBed } from '@angular/core/testing';
import { afterEach, describe, expect, it } from 'vitest';
import { CHECKLIST } from '@/app/core/testing/checklists.fixtures';
import { BASE, buttonIn, mountOnPage, textOf } from './checklist-page.testing';
import { ChecklistRefusal } from './checklist-refusal';

/** A refusal, explained: the sentence as the page built it, and a reload only where reloading cures it. */
describe('a checklist refusal', () => {
    afterEach(() => TestBed.resetTestingModule());

    it('offers to read everything again when reloading is the remedy, and reads it', () => {
        const { dom, fixture, http } = mountOnPage(
            ChecklistRefusal,
            { view: CHECKLIST },
            { refusal: { message: 'Somebody changed this checklist.', reload: true, itemId: null } }
        );
        expect(dom().querySelector('[role="alert"]')).not.toBeNull();
        expect(textOf(dom(), '[data-testid="refusal-message"]')).toBe('Somebody changed this checklist.');

        buttonIn(dom(), 'reload-checklist').click();
        fixture.detectChanges();
        http.expectOne(`${BASE}/context`);
        http.expectOne(BASE);
    });

    it('offers no reload for a refusal reloading cannot cure', () => {
        const { dom } = mountOnPage(
            ChecklistRefusal,
            { view: CHECKLIST },
            { refusal: { message: 'Four-eyes approval.', reload: false, itemId: null } }
        );
        expect(dom().querySelector('#reload-checklist')).toBeNull();
    });
});
