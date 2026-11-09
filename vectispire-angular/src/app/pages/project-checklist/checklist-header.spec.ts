import { TestBed } from '@angular/core/testing';
import { afterEach, describe, expect, it } from 'vitest';
import type { ChecklistView } from '@/app/core/api.models';
import { CHECKLIST, SIGNED_CHECKLIST, SIGNED_REVISION } from '@/app/core/testing/checklists.fixtures';
import { mountOnPage, textOf } from './checklist-page.testing';
import { ChecklistHeader } from './checklist-header';
import { PUBLIC_KEY_PATH } from './checklist-model';

/**
 * The header of the revision shown, on its own: its status and its automatic answers at a glance, why a
 * reader cannot write, and the document — called signed only when the status can say so, with the
 * guide's commands for that one alone.
 */
describe('the header of a project checklist', () => {
    afterEach(() => TestBed.resetTestingModule());

    const automatic: ChecklistView = {
        ...CHECKLIST,
        lines: CHECKLIST.lines.map((line, index) =>
            index === 0 && line.answer ? { ...line, answer: { ...line.answer, answeredByKind: 'system' } } : line
        )
    };

    it('states the status and how many answers Vectispire wrote', () => {
        const { dom } = mountOnPage(ChecklistHeader, { view: automatic });
        expect(textOf(dom(), '[data-testid="status"]')).toBe('Draft');
        expect(textOf(dom(), '[data-testid="automatic-count"]')).toBe('1 automatic answer');
    });

    it('calls a draft document an unsigned rendering, and gives no verification for it', () => {
        const { dom } = mountOnPage(ChecklistHeader, { view: CHECKLIST });
        expect(textOf(dom(), '#download-document')).toBe('Download an unsigned rendering');
        expect(dom().querySelector('[data-testid="verification"]')).toBeNull();
    });

    it('calls a signed-off document a signed package, with the commands that verify it', () => {
        const { dom } = mountOnPage(ChecklistHeader, {
            view: SIGNED_CHECKLIST,
            revisions: [SIGNED_CHECKLIST.checklist, SIGNED_REVISION]
        });
        expect(textOf(dom(), '#download-document')).toBe('Download the signed package');
        expect(dom().querySelector('[data-testid="public-key-link"]')!.getAttribute('href')).toBe(PUBLIC_KEY_PATH);
        expect(textOf(dom(), '[data-testid="verification-commands"]')).toContain(
            `unzip checklist-project-7-revision-${SIGNED_CHECKLIST.checklist.revision}.zip`
        );
    });

    it('tells a reader on an earlier revision that it never changes again', () => {
        const { dom } = mountOnPage(ChecklistHeader, {
            view: { ...SIGNED_CHECKLIST, checklist: SIGNED_REVISION },
            revisions: [CHECKLIST.checklist, SIGNED_REVISION]
        });
        expect(textOf(dom(), '[data-testid="read-only-old"]')).toBe(
            'An earlier revision, shown as it stands: it is never changed again.'
        );
    });
});
