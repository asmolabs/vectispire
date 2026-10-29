import { HttpErrorResponse } from '@angular/common/http';
import { TestBed } from '@angular/core/testing';
import { afterEach, describe, expect, it } from 'vitest';
import { of, throwError } from 'rxjs';
import type { ChecklistView } from '@/app/core/api.models';
import { CHECKLIST, CONTEXT, DRAFT_REVISION, SIGNED_REVISION } from '@/app/core/testing/checklists.fixtures';
import { ChecklistPage } from './checklist-page';
import { ChecklistRefusal } from './checklist-refusal';
import { mountOnPage } from './checklist-page.testing';

/**
 * The page's state on its own: the one way a write lands — the view adopted, the revision's row and the
 * context's edition following it — and a refusal explained from its problem type.
 */
describe('the state of the project checklist screen', () => {
    afterEach(() => TestBed.resetTestingModule());

    const refusal = (type: string, extra: Record<string, unknown> = {}) =>
        new HttpErrorResponse({
            status: 409,
            error: { type, title: 'Conflict', status: 409, detail: 'English.', ...extra }
        });

    function seeded(): ChecklistPage {
        const { page } = mountOnPage(
            ChecklistRefusal,
            { view: CHECKLIST },
            {
                refusal: { message: '', reload: false, itemId: null }
            }
        );
        page.context.set(CONTEXT);
        return page;
    }

    it('adopts the view a write answers: its row in the list and the context edition follow', () => {
        const page = seeded();
        const after: ChecklistView = { ...CHECKLIST, checklist: { ...CHECKLIST.checklist, edition: 6 } };
        page.refusal.set({ message: 'old', reload: false, itemId: null });

        let done = false;
        page.write(of(after), null, () => (done = true));

        expect(done).toBe(true);
        expect(page.view()).toBe(after);
        expect(page.refusal()).toBeNull();
        expect(page.revisions().map((row) => [row.revision, row.edition])).toEqual([
            [DRAFT_REVISION.revision, 6],
            [SIGNED_REVISION.revision, SIGNED_REVISION.edition]
        ]);
        expect(page.context()?.latestEdition).toBe(6);
        expect(page.busy()).toBe(false);
    });

    it('explains a four-eyes refusal with the authors, and offers no reload', () => {
        const page = seeded();
        page.write(
            throwError(() => refusal('urn:vectispire:problem:checklist-four-eyes')),
            null
        );
        expect(page.refusal()).toEqual({
            message:
                'Four-eyes approval: you wrote part of this revision, so a second person must sign it off. Written by: carol, dave.',
            reload: false,
            itemId: null
        });
    });

    it('keeps the lines an incomplete refusal names, by item, as the server found them', () => {
        const page = seeded();
        page.write(
            throwError(() =>
                refusal('urn:vectispire:problem:checklist-incomplete', {
                    lines: [{ itemId: 103, position: 3, problems: ['comment_required'] }]
                })
            ),
            103
        );
        expect(page.incomplete()).toEqual({ 103: ['comment_required'] });
        expect(page.refusal()?.itemId).toBe(103);
        expect(page.refusal()?.reload).toBe(true);
    });
});
