import { TestBed } from '@angular/core/testing';
import { afterEach, describe, expect, it } from 'vitest';
import { PREVIEW } from '@/app/core/testing/checklists.fixtures';
import { mountOnTemplates, textOf } from './templates-page.testing';
import { TemplateSheet } from './template-sheet';

/**
 * The sheet grid, on its own: the column heads name the fields the layout on screen gives them, the
 * item rows of named columns and the header cells are marked, and both follow the layout as it is typed.
 */
describe('the sheet of a checklist template', () => {
    afterEach(() => TestBed.resetTestingModule());

    const cell = (dom: HTMLElement, row: number, column: number) =>
        dom.querySelectorAll(`[data-testid="grid-row-${row}"] td`)[column] as HTMLElement;

    it('names the field each column holds, and marks the column header row', () => {
        const { dom } = mountOnTemplates(TemplateSheet, { preview: PREVIEW });
        expect(textOf(dom(), '[data-testid="grid-column-C"]')).toBe('C · Control');
        expect(dom().querySelector('[data-testid="grid-row-4"]')!.classList.contains('font-semibold')).toBe(true);
        expect(textOf(dom(), '[data-testid="column-header-row"]')).toContain('4');
    });

    it('marks the item rows of named columns, the header cells, and a formula', () => {
        const { dom } = mountOnTemplates(TemplateSheet, { preview: PREVIEW });
        // Columns A to F; row 5 is an item row, A2 the date's label cell, B2 a formula.
        expect(cell(dom(), 5, 2).className).toContain('bg-blue-100');
        expect(cell(dom(), 2, 0).className).toContain('bg-amber-100');
        expect(cell(dom(), 2, 1).textContent).toContain('ƒ');
        expect(cell(dom(), 4, 2).className).not.toContain('bg-blue-100');
    });

    it('follows the layout as it is typed', () => {
        const { dom, fixture, page } = mountOnTemplates(TemplateSheet, { preview: PREVIEW });
        page.layoutDraft.update((draft) => (draft ? { ...draft, columns: { ...draft.columns, kpi: '' } } : draft));
        page.setDraft({ lastItemRow: 6 });
        fixture.detectChanges();
        expect(textOf(dom(), '[data-testid="grid-column-D"]')).toBe('D');
        // Row 5 is still an item row, but D names no field any more: its cell is not one of the items'.
        expect(cell(dom(), 5, 3).className).not.toContain('bg-blue-100');
        expect(cell(dom(), 5, 2).className).toContain('bg-blue-100');
        expect(cell(dom(), 7, 2).className).not.toContain('bg-blue-100');
    });
});
