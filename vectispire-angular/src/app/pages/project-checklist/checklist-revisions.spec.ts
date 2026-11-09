import { TestBed } from '@angular/core/testing';
import { afterEach, describe, expect, it } from 'vitest';
import { CHECKLIST, DRAFT_REVISION, SIGNED_REVISION } from '@/app/core/testing/checklists.fixtures';
import { useFrench } from '@/app/core/testing/english';
import { BASE, buttonIn, mountOnPage, textOf } from './checklist-page.testing';
import { ChecklistRevisions } from './checklist-revisions';

/**
 * The list of revisions, on its own: each status in words, the one on screen tagged rather than offered,
 * an earlier one read on request, and the words following a switch of language.
 */
describe('the revisions of a project checklist', () => {
    afterEach(() => TestBed.resetTestingModule());

    it('states each revision, tags the one shown, and reads another on request', () => {
        const { dom, fixture, http, page } = mountOnPage(ChecklistRevisions, { view: CHECKLIST });
        expect(textOf(dom(), `[data-testid="revision-${DRAFT_REVISION.revision}"] p-tag`)).toBe('Draft');
        expect(textOf(dom(), `[data-testid="revision-${DRAFT_REVISION.revision}"]`)).toContain('Shown');
        expect(textOf(dom(), `[data-testid="revision-${SIGNED_REVISION.revision}"] p-tag`)).toBe('Signed off');

        buttonIn(dom(), `Read revision ${SIGNED_REVISION.revision}`).click();
        fixture.detectChanges();
        http.expectOne(`${BASE}/${SIGNED_REVISION.revision}`);
        expect(page.loading()).toBe(true);
    });

    it('names each download by whether the document is signed', () => {
        const { dom } = mountOnPage(ChecklistRevisions, { view: CHECKLIST });
        const label = (revision: number) =>
            dom().querySelector(`[data-testid="download-document-${revision}"] button`)!.getAttribute('aria-label');
        expect(label(SIGNED_REVISION.revision)).toContain('signed package');
        expect(label(DRAFT_REVISION.revision)).toContain('unsigned');
    });

    it('rewrites the statuses when the language changes', () => {
        const { dom, fixture } = mountOnPage(ChecklistRevisions, { view: CHECKLIST });
        useFrench();
        fixture.detectChanges();
        expect(textOf(dom(), `[data-testid="revision-${DRAFT_REVISION.revision}"] p-tag`)).toBe('Brouillon');
        expect(textOf(dom(), `[data-testid="revision-${SIGNED_REVISION.revision}"] p-tag`)).toBe('Approuvée');
    });
});
