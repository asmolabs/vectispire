import { ChangeDetectionStrategy, Component, computed, inject } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { MessageModule } from '@openng/optimus-ui/message';
import { SelectModule } from '@openng/optimus-ui/select';
import type { ChecklistColumn, ChecklistHeaderField } from '../../core/api.models';
import { I18nService } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { COLUMN_KEYS, COLUMNS, gridOf, HEADER_FIELDS } from './templates-model';
import { TemplatesPage } from './templates-page';

const HEADER_CELL = 'bg-amber-100 dark:bg-amber-900/40';
const ITEM_CELL = 'bg-blue-100 dark:bg-blue-950/40';

/**
 * The sheet as the reader sees it, with the layout on screen drawn over it: the item rows of the named
 * columns in blue, the header cells in amber, each column head naming the fields it holds.
 *
 * The grid is computed whole, cell by cell, when the preview or the layout typed changes — not asked of
 * a method per cell on every pass: a sheet holds thousands of cells.
 */
@Component({
    selector: 'app-template-sheet',
    imports: [FormsModule, MessageModule, SelectModule, TranslatePipe],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './template-sheet.html'
})
export class TemplateSheet {
    private readonly i18n = inject(I18nService);
    protected readonly page = inject(TemplatesPage);

    private readonly grid = computed(() => gridOf(this.page.preview()?.cells ?? []));
    protected readonly sheetOptions = computed(() =>
        (this.page.preview()?.sheets ?? []).map((sheet) => ({ label: sheet, value: sheet }))
    );

    /** Which field each column letter holds in the layout on screen — what the grid's column heads name. */
    private readonly fieldsOfColumn = computed(() => {
        const fields = new Map<string, ChecklistColumn[]>();
        const draft = this.page.layoutDraft();
        if (!draft) return fields;
        for (const column of COLUMNS) {
            const letters = draft.columns[column].trim().toUpperCase();
            if (letters) fields.set(letters, [...(fields.get(letters) ?? []), column]);
        }
        return fields;
    });

    private readonly headerCells = computed(() => {
        const cells = new Map<string, ChecklistHeaderField>();
        const draft = this.page.layoutDraft();
        if (!draft) return cells;
        for (const field of HEADER_FIELDS) {
            for (const ref of [draft.header[field].label, draft.header[field].value]) {
                if (ref.trim()) cells.set(ref.trim().toUpperCase(), field);
            }
        }
        return cells;
    });

    /** "C · control", or the letters alone for a column the layout does not name. */
    protected readonly heads = computed(() =>
        this.grid().columns.map((letters) => {
            const fields = this.fieldsOfColumn().get(letters);
            return {
                letters,
                named: !!fields,
                text: fields
                    ? `${letters} · ${fields.map((field) => this.i18n.t(COLUMN_KEYS[field])).join(', ')}`
                    : letters
            };
        })
    );

    protected readonly rows = computed(() => {
        const draft = this.page.layoutDraft();
        const headerRow = this.page.preview()?.proposal.columnHeaderRow;
        const columns = this.grid().columns;
        return this.grid().rows.map((line) => {
            const itemRow =
                draft?.firstItemRow != null &&
                draft.lastItemRow != null &&
                line.row >= draft.firstItemRow &&
                line.row <= draft.lastItemRow;
            return {
                row: line.row,
                headerRow: headerRow === line.row,
                itemRow,
                cells: columns.map((letters) => {
                    const cell = line.cells[letters];
                    return {
                        letters,
                        text: cell?.text ?? '',
                        title: cell?.text ?? null,
                        formula: !!cell?.formula,
                        class: this.headerCells().has(`${letters}${line.row}`)
                            ? HEADER_CELL
                            : itemRow && this.fieldsOfColumn().has(letters)
                              ? ITEM_CELL
                              : ''
                    };
                })
            };
        });
    });
}
