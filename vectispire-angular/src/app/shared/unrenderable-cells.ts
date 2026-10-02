import type { ChecklistUnrenderableCell } from '../core/api.models';
import { I18nService } from '../core/i18n/i18n.service';

/**
 * The cells a workbook's trial rendering refused, **written once for both screens**: the template screen
 * meets them at publication (`checklist-template-unrenderable`), the project checklist when it is opened
 * on, or moved to, a version published before that check (`checklist-version-unrenderable`). The person
 * correcting the workbook needs each cell and the range depending on it, in their own language; the
 * server's English `detail` names them too, but a screen that knows the cause does not show it.
 */

/**
 * The cells a refusal names in its `cells` member, or `null` when it names none the screen can read — a
 * workbook refused for another reason, or a shape it does not expect — so that the caller falls back on
 * the server's own words rather than on a sentence listing nothing.
 */
export function unrenderableCellsOf(failure: unknown): ChecklistUnrenderableCell[] | null {
    const cells = (failure as { error?: { cells?: unknown } } | null)?.error?.cells;
    if (!Array.isArray(cells)) return null;
    const read = cells.filter(
        (cell): cell is ChecklistUnrenderableCell =>
            typeof (cell as ChecklistUnrenderableCell | null)?.cell === 'string' &&
            typeof (cell as ChecklistUnrenderableCell).range === 'string' &&
            ((cell as ChecklistUnrenderableCell).kind === 'shared' ||
                (cell as ChecklistUnrenderableCell).kind === 'array')
    );
    return read.length > 0 ? read : null;
}

/** Each cell with what it holds — `G7 (the master of a formula shared across G7:G9)` — in the reader's language. */
export function describeUnrenderableCells(i18n: I18nService, cells: readonly ChecklistUnrenderableCell[]): string {
    return cells
        .map((one) =>
            one.kind === 'array'
                ? i18n.t('checklist_cells.array', { cell: one.cell, range: one.range })
                : i18n.t('checklist_cells.shared', { cell: one.cell, range: one.range })
        )
        .join(', ');
}
