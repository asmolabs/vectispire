import type {
    ChecklistChange,
    ChecklistColumn,
    ChecklistEvidenceKind,
    ChecklistHeaderField,
    ChecklistItem,
    ChecklistItemEvidence,
    ChecklistItemRule,
    ChecklistLayout,
    ChecklistPreview,
    ChecklistPreviewCell,
    ChecklistRule,
    ChecklistVersionStatus
} from '../../core/api.models';
import { I18nService } from '../../core/i18n/i18n.service';
import { keyFor } from '../../core/i18n/literal-keys';
import { canonicalRule } from '../../shared/checklist-rules';

/*
 * The checklist templates' words and judgements, shared by the screen and the components it is made of:
 * the columns and header fields a layout names, literal keys for every value the server sends, the
 * refusals it names by type, and the pure helpers that read and check a layout. Nothing here holds
 * state or reaches the server — that is `TemplatesPage`.
 */

/** In the order the form lists them: the sheet's reading order, left to right, as a template usually runs. */
export const COLUMNS: readonly ChecklistColumn[] = [
    'id',
    'domain',
    'objective',
    'control',
    'contact',
    'kpi',
    'answer',
    'comment'
];
/** Without them no item can be read (control) nor an answer written (answer, comment) — `ChecklistColumn.required()`. */
export const REQUIRED_COLUMNS: readonly ChecklistColumn[] = ['control', 'answer', 'comment'];
export const HEADER_FIELDS: readonly ChecklistHeaderField[] = ['date', 'product', 'author'];

/** The server's own slug rule (`ChecklistTemplateService.SLUG`): what a URL segment reads without escaping. */
export const SLUG = /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/;
/** A column's letters, `A` to `XFD`; the server refuses anything else in words. */
export const LETTERS = /^[A-Za-z]{1,3}$/;
/** A cell, `B3`. */
export const CELL = /^[A-Za-z]{1,3}[1-9][0-9]{0,6}$/;

// Literal keys, so the i18n check sees each one and a new value cannot ship as a raw key (decision
// 0019). The check counts none of these — they are not `t('…')` calls — so the spec reads each
// against both bundles.
export const COLUMN_KEYS = {
    id: 'checklist_templates.column_id',
    domain: 'checklist_templates.column_domain',
    objective: 'checklist_templates.column_objective',
    control: 'checklist_templates.column_control',
    contact: 'checklist_templates.column_contact',
    kpi: 'checklist_templates.column_kpi',
    answer: 'checklist_templates.column_answer',
    comment: 'checklist_templates.column_comment'
} as const satisfies Record<ChecklistColumn, string>;

export const HEADER_KEYS = {
    date: 'checklist_templates.header_date',
    product: 'checklist_templates.header_product',
    author: 'checklist_templates.header_author'
} as const satisfies Record<ChecklistHeaderField, string>;

export const STATUS_KEYS = {
    draft: 'checklist_templates.status_draft',
    published: 'checklist_templates.status_published',
    retired: 'checklist_templates.status_retired'
} as const satisfies Record<ChecklistVersionStatus, string>;

export const CHANGE_KEYS = {
    unchanged: 'checklist_templates.change_unchanged',
    changed: 'checklist_templates.change_changed',
    added: 'checklist_templates.change_added',
    removed: 'checklist_templates.change_removed'
} as const satisfies Record<ChecklistChange, string>;

/**
 * Why the server refused a template write for the state it found: `ChecklistConflict.Cause`, read
 * from the problem's `type` — never from its English `detail`. It used to be guessed by reading the
 * version again, which could only tell apart the causes a version's summary shows, and cost a
 * request to do it.
 */
export type TemplateConflict =
    | 'changed'
    | 'not_draft'
    | 'no_layout'
    | 'has_draft'
    | 'not_published'
    | 'retired'
    | 'nothing_to_pair'
    | 'unrenderable'
    | 'four_eyes';

/** `ApiExceptionHandler.PROBLEM_TYPE` followed by `Cause.token()`, one per cause the template routes name. */
export const CONFLICT_TYPES: Readonly<Record<string, TemplateConflict>> = {
    'urn:vectispire:problem:checklist-template-changed': 'changed',
    'urn:vectispire:problem:checklist-template-not-draft': 'not_draft',
    'urn:vectispire:problem:checklist-template-no-layout': 'no_layout',
    'urn:vectispire:problem:checklist-template-has-draft': 'has_draft',
    'urn:vectispire:problem:checklist-template-not-published': 'not_published',
    'urn:vectispire:problem:checklist-template-retired': 'retired',
    'urn:vectispire:problem:checklist-template-nothing-to-pair': 'nothing_to_pair',
    'urn:vectispire:problem:checklist-template-unrenderable': 'unrenderable',
    // The project checklists' token, shared because it means the same on both.
    'urn:vectispire:problem:checklist-four-eyes': 'four_eyes'
};

/** A cause as the screen words it: under four-eyes, which act the second person must make. */
export type Refusal = Exclude<TemplateConflict, 'four_eyes'> | 'four_eyes_publish' | 'four_eyes_retire';

export const REFUSAL_KEYS = {
    changed: 'checklist_templates.refusal_changed',
    not_draft: 'checklist_templates.refusal_not_draft',
    no_layout: 'checklist_templates.refusal_no_layout',
    has_draft: 'checklist_templates.refusal_has_draft',
    not_published: 'checklist_templates.refusal_not_published',
    retired: 'checklist_templates.refusal_retired',
    nothing_to_pair: 'checklist_templates.refusal_nothing_to_pair',
    unrenderable: 'checklist_templates.refusal_unrenderable',
    four_eyes_publish: 'checklist_templates.refusal_four_eyes_publish',
    four_eyes_retire: 'checklist_templates.refusal_four_eyes_retire'
} as const satisfies Record<Refusal, string>;

/**
 * Whether reading the version again is the remedy — it is wherever the screen was behind the
 * server. Not under four-eyes, since the person is who they are, nor for a first version, which
 * reloading does not give a predecessor.
 */
export const REFUSAL_RELOADS = {
    changed: true,
    not_draft: true,
    no_layout: true,
    has_draft: true,
    not_published: true,
    retired: true,
    nothing_to_pair: false,
    // The workbook is what is wrong, and a version's workbook never changes: reading it again shows the same.
    unrenderable: false,
    four_eyes_publish: false,
    four_eyes_retire: false
} as const satisfies Record<Refusal, boolean>;

/** In the order the form offers them: from asking nothing to asking the most. */
export const EVIDENCE_KINDS: readonly ChecklistEvidenceKind[] = ['none', 'link_or_file', 'file'];

export const EVIDENCE_KIND_KEYS = {
    none: 'checklist_templates.evidence_kind_none',
    link_or_file: 'checklist_templates.evidence_kind_link_or_file',
    file: 'checklist_templates.evidence_kind_file'
} as const satisfies Record<ChecklistEvidenceKind, string>;

/** `ChecklistTemplateService`'s bounds on a proof's validity, in months. */
export const MIN_VALIDITY_MONTHS = 1;
export const MAX_VALIDITY_MONTHS = 120;

/** A line's requirement as the form edits it, before it is sent. */
export interface EvidenceEdit {
    kind: ChecklistEvidenceKind;
    months: number | null;
}

/** What the client refuses before sending a layout; the server has the last word, in its own. */
export const PROBLEM_KEYS = {
    sheet: 'checklist_templates.problem_sheet',
    required: 'checklist_templates.problem_required',
    letters: 'checklist_templates.problem_letters',
    rows: 'checklist_templates.problem_rows',
    header_cells: 'checklist_templates.problem_header',
    words: 'checklist_templates.problem_words',
    not_applicable: 'checklist_templates.problem_not_applicable'
} as const;
export type LayoutProblem = keyof typeof PROBLEM_KEYS;

/** The layout being confirmed — or, read-only, the one shown — as the form edits it. */
export interface LayoutDraft {
    sheet: string;
    columns: Record<ChecklistColumn, string>;
    firstItemRow: number | null;
    lastItemRow: number | null;
    header: Record<ChecklistHeaderField, { label: string; value: string }>;
    yes: string;
    no: string;
    offersNotApplicable: boolean;
    notApplicable: string;
}

/** A sheet laid out as rows and columns, only the rows and columns holding something. */
export interface Grid {
    columns: string[];
    rows: { row: number; cells: Record<string, ChecklistPreviewCell> }[];
}

// ---------------------------------------------------------------------- pure helpers

/** A column's letters as a number, `A` = 1, `AA` = 27 — the sheet's order, which alphabetical is not. */
export function columnIndex(letters: string): number {
    let index = 0;
    for (const letter of letters.toUpperCase()) index = index * 26 + (letter.charCodeAt(0) - 64);
    return index;
}

export function gridOf(cells: ChecklistPreviewCell[]): Grid {
    const columns = [...new Set(cells.map((cell) => cell.column.toUpperCase()))].sort(
        (a, b) => columnIndex(a) - columnIndex(b)
    );
    const rows = new Map<number, Record<string, ChecklistPreviewCell>>();
    for (const cell of cells) {
        const row = rows.get(cell.row) ?? {};
        row[cell.column.toUpperCase()] = cell;
        rows.set(cell.row, row);
    }
    return {
        columns,
        rows: [...rows.entries()].sort((a, b) => a[0] - b[0]).map(([row, rowCells]) => ({ row, cells: rowCells }))
    };
}

/**
 * The layout the form starts from: the confirmed one when a person confirmed it, else the reader's
 * proposal. **The answer words are never guessed** from the proposal's list: which word means "yes"
 * is the organisation's vocabulary, and a mapping by position would be a guess nobody made.
 */
export function draftFrom(preview: ChecklistPreview): LayoutDraft {
    const source = preview.layout ?? preview.proposal;
    const columns = Object.fromEntries(COLUMNS.map((column) => [column, source.columns[column] ?? ''])) as Record<
        ChecklistColumn,
        string
    >;
    const header = Object.fromEntries(
        HEADER_FIELDS.map((field) => [
            field,
            { label: source.header[field]?.label ?? '', value: source.header[field]?.value ?? '' }
        ])
    ) as LayoutDraft['header'];
    const answers = preview.layout?.answers;
    return {
        sheet: source.sheet ?? preview.sheet,
        columns,
        firstItemRow: source.firstItemRow ?? null,
        lastItemRow: source.lastItemRow ?? null,
        header,
        yes: answers?.yes ?? '',
        no: answers?.no ?? '',
        offersNotApplicable: !!answers?.notApplicable,
        notApplicable: answers?.notApplicable ?? ''
    };
}

/** What the client refuses before sending; `null` when the server is the one left to judge. */
export function layoutProblem(draft: LayoutDraft): LayoutProblem | null {
    if (!draft.sheet.trim()) return 'sheet';
    if (REQUIRED_COLUMNS.some((column) => !draft.columns[column].trim())) return 'required';
    if (COLUMNS.some((column) => draft.columns[column].trim() && !LETTERS.test(draft.columns[column].trim()))) {
        return 'letters';
    }
    const first = draft.firstItemRow;
    const last = draft.lastItemRow;
    if (
        first == null ||
        last == null ||
        !Number.isInteger(first) ||
        !Number.isInteger(last) ||
        first < 1 ||
        first > last
    ) {
        return 'rows';
    }
    for (const field of HEADER_FIELDS) {
        const { label, value } = draft.header[field];
        const named = [label.trim(), value.trim()].filter((ref) => ref);
        // Both cells or neither: a header entry is a label the renderer leaves and a value it writes.
        if (named.length === 1 || named.some((ref) => !CELL.test(ref))) return 'header_cells';
    }
    if (!draft.yes.trim() || !draft.no.trim()) return 'words';
    if (draft.offersNotApplicable && !draft.notApplicable.trim()) return 'not_applicable';
    return null;
}

/** The body the route reads: blank columns and header entries left out, letters in capitals. */
export function layoutOf(draft: LayoutDraft): ChecklistLayout {
    const columns: Partial<Record<ChecklistColumn, string>> = {};
    for (const column of COLUMNS) {
        const letters = draft.columns[column].trim().toUpperCase();
        if (letters) columns[column] = letters;
    }
    const header: ChecklistLayout['header'] = {};
    for (const field of HEADER_FIELDS) {
        const label = draft.header[field].label.trim().toUpperCase();
        const value = draft.header[field].value.trim().toUpperCase();
        if (label && value) header[field] = { label, value };
    }
    return {
        sheet: draft.sheet,
        columns,
        firstItemRow: draft.firstItemRow!,
        lastItemRow: draft.lastItemRow!,
        header,
        answers: {
            yes: draft.yes.trim(),
            no: draft.no.trim(),
            notApplicable: draft.offersNotApplicable ? draft.notApplicable.trim() : null
        }
    };
}

/** The server's comparison (`Editor.wrote`) on the side it can be made here: the name, without case. */
export function wrote(authors: string[], username: string | null | undefined): boolean {
    const me = username?.trim().toLowerCase();
    return !!me && authors.some((author) => author.trim().toLowerCase() === me);
}

/**
 * The lines whose requirement the form changed, in the version's order, as the route reads them. A
 * line edited back to what it was is not sent; a line asking for no proof is sent without a validity.
 */
export function evidenceChangesOf(
    items: ChecklistItem[],
    edits: Record<string, EvidenceEdit>
): ChecklistItemEvidence[] {
    const changes: ChecklistItemEvidence[] = [];
    for (const item of items) {
        const edit = edits[item.itemKey];
        if (!edit) continue;
        const months = edit.kind === 'none' ? null : edit.months;
        if (edit.kind === item.evidenceKind && months === item.evidenceValidityMonths) continue;
        changes.push({ itemKey: item.itemKey, evidenceKind: edit.kind, evidenceValidityMonths: months });
    }
    return changes;
}

/**
 * The lines whose rule the form changed, in the version's order, as the route reads them. A line edited
 * back to the rule it has is not sent: the comparison is on the canonical form, keys sorted, so a rule
 * reopened and kept as it was is no change.
 */
export function ruleChangesOf(
    items: ChecklistItem[],
    edits: Record<string, ChecklistRule | null>
): ChecklistItemRule[] {
    const changes: ChecklistItemRule[] = [];
    for (const item of items) {
        if (!(item.itemKey in edits)) continue;
        const rule = edits[item.itemKey];
        if (canonicalRule(rule) === canonicalRule(item.boundRule)) continue;
        changes.push({ itemKey: item.itemKey, rule });
    }
    return changes;
}

/** The server's bounds: no validity, or a whole number of months from 1 to 120 — never on a line asking nothing. */
export function validityAllowed(change: ChecklistItemEvidence): boolean {
    const months = change.evidenceValidityMonths;
    if (months === null) return true;
    return (
        change.evidenceKind !== 'none' &&
        Number.isInteger(months) &&
        months >= MIN_VALIDITY_MONTHS &&
        months <= MAX_VALIDITY_MONTHS
    );
}

/** The cause a template refusal names in its problem type, or `null` for any other failure. */
export function conflictOf(failure: unknown): TemplateConflict | null {
    const type = (failure as { error?: { type?: unknown } } | null)?.error?.type;
    return typeof type === 'string' ? (CONFLICT_TYPES[type] ?? null) : null;
}

// ---------------------------------------------------------------------- labels

/** A status in words; one the client does not know is shown as sent. */
export function statusLabel(i18n: I18nService, status: string): string {
    const key = keyFor(STATUS_KEYS, status);
    return key ? i18n.t(key) : status;
}

export function statusSeverity(status: string): 'warn' | 'success' | 'secondary' {
    return status === 'draft' ? 'warn' : status === 'published' ? 'success' : 'secondary';
}

export function changeLabel(i18n: I18nService, change: string): string {
    const key = keyFor(CHANGE_KEYS, change);
    return key ? i18n.t(key) : change;
}

export function changeSeverity(change: string): 'secondary' | 'warn' | 'info' | 'danger' {
    return change === 'unchanged'
        ? 'secondary'
        : change === 'changed'
          ? 'warn'
          : change === 'added'
            ? 'info'
            : 'danger';
}

export function evidenceKindLabel(i18n: I18nService, kind: string): string {
    const key = keyFor(EVIDENCE_KIND_KEYS, kind);
    return key ? i18n.t(key) : kind;
}
