import { CommonModule } from '@angular/common';
import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import type { Observable } from 'rxjs';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { CheckboxModule } from '@openng/optimus-ui/checkbox';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { SelectModule } from '@openng/optimus-ui/select';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import { messageOf } from '../../core/api-error';
import { ChecklistsApi, MAX_WORKBOOK_BYTES } from '../../core/api/checklists.api';
import type {
    ChecklistChange,
    ChecklistColumn,
    ChecklistHeaderField,
    ChecklistItemPair,
    ChecklistLayout,
    ChecklistPairingChange,
    ChecklistPreview,
    ChecklistPreviewCell,
    ChecklistTemplate,
    ChecklistVersion,
    ChecklistVersionStatus
} from '../../core/api.models';
import { I18nService } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { LatestRequest } from '../../core/latest-request';
import { SessionStore } from '../../core/session.store';

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
const LETTERS = /^[A-Za-z]{1,3}$/;
/** A cell, `B3`. */
const CELL = /^[A-Za-z]{1,3}[1-9][0-9]{0,6}$/;

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
    'changed' | 'not_draft' | 'no_layout' | 'has_draft' | 'not_published' | 'retired' | 'nothing_to_pair' | 'four_eyes';

/** `ApiExceptionHandler.PROBLEM_TYPE` followed by `Cause.token()`, one per cause the template routes name. */
export const CONFLICT_TYPES: Readonly<Record<string, TemplateConflict>> = {
    'urn:vectispire:problem:checklist-template-changed': 'changed',
    'urn:vectispire:problem:checklist-template-not-draft': 'not_draft',
    'urn:vectispire:problem:checklist-template-no-layout': 'no_layout',
    'urn:vectispire:problem:checklist-template-has-draft': 'has_draft',
    'urn:vectispire:problem:checklist-template-not-published': 'not_published',
    'urn:vectispire:problem:checklist-template-retired': 'retired',
    'urn:vectispire:problem:checklist-template-nothing-to-pair': 'nothing_to_pair',
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
    four_eyes_publish: false,
    four_eyes_retire: false
} as const satisfies Record<Refusal, boolean>;

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

/**
 * The organisation's checklist templates (decision 0032 §3, §4, §8).
 *
 * **Never published in one step.** A workbook becomes a draft; the reader's proposal is shown on the
 * sheet's own cells, a person confirms or corrects each column letter, the item rows, the header
 * cells and the template's answer words; the items are paired with the previous version; then it is
 * published — naming the revision on screen, so that an edit made meanwhile refuses the publication
 * rather than publishing something nobody here has read.
 *
 * Reading is governance, the auditor included; every write is a security lead's (platform governor,
 * administrator, CISO), and a reader who may not write is shown no write control at all rather than
 * controls the server would refuse. With four-eyes on, the server refuses an author of a draft as its
 * publisher. A 409 is explained from the cause its problem type names, never from its English.
 */
@Component({
    selector: 'app-checklist-templates',
    standalone: true,
    imports: [
        CommonModule,
        FormsModule,
        ButtonModule,
        CardModule,
        CheckboxModule,
        InputTextModule,
        MessageModule,
        SelectModule,
        TableModule,
        TagModule,
        TranslatePipe
    ],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './checklist-templates.html'
})
export class ChecklistTemplates {
    private readonly api = inject(ChecklistsApi);
    private readonly i18n = inject(I18nService);
    private readonly session = inject(SessionStore);
    // Two streams: switching sheets must not cancel the items, and an older preview must not land
    // over a newer one when the reader clicks through sheets faster than the server answers.
    private readonly previewRequest = new LatestRequest();
    private readonly versionRequest = new LatestRequest();

    readonly columns = COLUMNS;
    readonly headerFields = HEADER_FIELDS;
    readonly required = REQUIRED_COLUMNS;
    readonly maxWorkbookBytes = MAX_WORKBOOK_BYTES;

    /** The server's `@RequiresSecurityLead`: who is offered a write control. */
    readonly writes = this.session.isSecurityLead;

    readonly templates = signal<ChecklistTemplate[]>([]);
    readonly loading = signal(true);
    readonly error = signal<string | null>(null);
    readonly notice = signal<string | null>(null);

    // The import form.
    readonly uploadSlug = signal('');
    readonly uploadName = signal('');
    readonly uploadLabel = signal('');
    readonly uploadFile = signal<File | null>(null);
    readonly uploadError = signal<string | null>(null);
    readonly uploading = signal(false);
    readonly isNewTemplate = computed(() => !this.templates().some((one) => one.slug === this.uploadSlug().trim()));

    // The version open below the list.
    readonly selected = signal<{ slug: string; ordinal: number } | null>(null);
    readonly preview = signal<ChecklistPreview | null>(null);
    readonly version = signal<ChecklistVersion | null>(null);
    readonly previewLoading = signal(false);
    readonly panelError = signal<string | null>(null);
    readonly layoutDraft = signal<LayoutDraft | null>(null);
    readonly formError = signal<string | null>(null);
    readonly busy = signal(false);
    /** A refusal explained, and whether reloading is what it asks for. */
    readonly refusal = signal<{ message: string; reload: boolean } | null>(null);
    readonly confirming = signal<'publish' | 'retire' | null>(null);
    readonly deriveLabel = signal('');
    readonly pairAdded = signal<string | null>(null);
    readonly pairRemoved = signal<string | null>(null);

    /** What the panel shows, and what publishing names: the preview's summary, read with the cells. */
    readonly shown = computed(() => this.preview()?.version ?? null);
    readonly editable = computed(() => this.writes() && this.shown()?.status === 'draft');
    readonly grid = computed(() => gridOf(this.preview()?.cells ?? []));
    readonly sheetOptions = computed(() =>
        (this.preview()?.sheets ?? []).map((sheet) => ({ label: sheet, value: sheet }))
    );
    readonly answerValues = computed(() => this.preview()?.proposal.answerValues ?? []);

    /** Which field each column letter holds in the layout on screen — what the grid's column heads name. */
    readonly fieldsOfColumn = computed(() => {
        const fields = new Map<string, ChecklistColumn[]>();
        const draft = this.layoutDraft();
        if (!draft) return fields;
        for (const column of COLUMNS) {
            const letters = draft.columns[column].trim().toUpperCase();
            if (letters) fields.set(letters, [...(fields.get(letters) ?? []), column]);
        }
        return fields;
    });
    readonly headerCells = computed(() => {
        const cells = new Map<string, ChecklistHeaderField>();
        const draft = this.layoutDraft();
        if (!draft) return cells;
        for (const field of HEADER_FIELDS) {
            for (const ref of [draft.header[field].label, draft.header[field].value]) {
                if (ref.trim()) cells.set(ref.trim().toUpperCase(), field);
            }
        }
        return cells;
    });

    readonly pairing = computed(() => this.preview()?.pairing ?? []);
    readonly pairingCounts = computed(() => {
        const counts: Record<ChecklistChange, number> = { unchanged: 0, changed: 0, added: 0, removed: 0 };
        for (const change of this.pairing()) counts[change.change] += 1;
        return counts;
    });
    readonly addedOptions = computed(() =>
        this.pairing()
            .filter((change) => change.change === 'added' && change.readKey)
            .map((change) => ({ value: change.readKey!, label: `${change.row ?? '?'} · ${change.control ?? ''}` }))
    );
    readonly removedOptions = computed(() =>
        this.pairing()
            .filter((change) => change.change === 'removed' && change.previousKey)
            .map((change) => ({
                value: change.previousKey!,
                label: `${change.previousRow ?? '?'} · ${change.previousControl ?? ''}`
            }))
    );
    /** Whether the signed-in account is among the draft's authors — who, under four-eyes, may not publish it. */
    readonly wroteShown = computed(() => wrote(this.shown()?.draftAuthors ?? [], this.session.user()?.username));

    constructor() {
        this.reload();
    }

    reload(): void {
        this.loading.set(true);
        this.api.checklistTemplates().subscribe({
            next: (templates) => {
                this.templates.set(templates);
                this.loading.set(false);
            },
            error: (failure) => {
                this.error.set(messageOf(failure, this.i18n.t('checklist_templates.error_load')));
                this.loading.set(false);
            }
        });
    }

    statusLabel(status: string): string {
        this.i18n.translations();
        const key = (STATUS_KEYS as Record<string, string | undefined>)[status];
        return key ? this.i18n.t(key) : status;
    }

    statusSeverity(status: string): 'warn' | 'success' | 'secondary' {
        return status === 'draft' ? 'warn' : status === 'published' ? 'success' : 'secondary';
    }

    changeLabel(change: string): string {
        this.i18n.translations();
        const key = (CHANGE_KEYS as Record<string, string | undefined>)[change];
        return key ? this.i18n.t(key) : change;
    }

    changeSeverity(change: string): 'secondary' | 'warn' | 'info' | 'danger' {
        return change === 'unchanged'
            ? 'secondary'
            : change === 'changed'
              ? 'warn'
              : change === 'added'
                ? 'info'
                : 'danger';
    }

    columnLabel(column: ChecklistColumn): string {
        this.i18n.translations();
        return this.i18n.t(COLUMN_KEYS[column]);
    }

    headerLabel(field: ChecklistHeaderField): string {
        this.i18n.translations();
        return this.i18n.t(HEADER_KEYS[field]);
    }

    hasDraft(template: ChecklistTemplate): boolean {
        return template.versions.some((version) => version.status === 'draft');
    }

    // ------------------------------------------------------------------ import

    /** Offers the next version of an existing template: the form, with its slug. */
    newVersionOf(template: ChecklistTemplate): void {
        this.uploadSlug.set(template.slug);
        this.uploadName.set('');
        this.uploadError.set(null);
        document.getElementById('checklist-file')?.focus();
    }

    /**
     * Refused past the route's ceiling before anything is sent, in the sentence the server would
     * answer with — a reader told one thing by the form and another by the server would reasonably
     * wonder which one is right.
     */
    pick(event: Event): void {
        const input = event.target as HTMLInputElement;
        const file = input.files?.[0] ?? null;
        this.uploadError.set(null);
        if (file && file.size > MAX_WORKBOOK_BYTES) {
            this.uploadFile.set(null);
            input.value = '';
            this.uploadError.set(this.i18n.t('checklist_templates.too_large', { limit: MAX_WORKBOOK_BYTES }));
            return;
        }
        this.uploadFile.set(file);
    }

    canImport(): boolean {
        return SLUG.test(this.uploadSlug().trim()) && this.uploadFile() !== null && !this.uploading();
    }

    importWorkbook(): void {
        const file = this.uploadFile();
        const slug = this.uploadSlug().trim();
        if (!file || !SLUG.test(slug)) return;
        this.uploading.set(true);
        this.uploadError.set(null);
        this.api
            .importChecklistWorkbook(slug, file, {
                name: this.isNewTemplate() ? this.uploadName() : null,
                label: this.uploadLabel()
            })
            .subscribe({
                next: (imported) => {
                    this.uploading.set(false);
                    this.uploadFile.set(null);
                    this.uploadLabel.set('');
                    const input = document.getElementById('checklist-file') as HTMLInputElement | null;
                    if (input) input.value = '';
                    this.notice.set(
                        this.i18n.t('checklist_templates.imported_notice', {
                            slug: imported.templateSlug,
                            ordinal: imported.version.ordinal
                        })
                    );
                    this.reload();
                    this.open(imported.templateSlug, imported.version.ordinal);
                },
                error: (failure) => {
                    this.uploading.set(false);
                    // The one cause an import meets, said by the form rather than by a panel that may
                    // show another version.
                    this.uploadError.set(
                        conflictOf(failure) === 'has_draft'
                            ? this.i18n.t(REFUSAL_KEYS.has_draft)
                            : messageOf(failure, this.i18n.t('checklist_templates.error_import'))
                    );
                }
            });
    }

    // ------------------------------------------------------------------ the version panel

    open(slug: string, ordinal: number): void {
        this.selected.set({ slug, ordinal });
        this.preview.set(null);
        this.version.set(null);
        this.layoutDraft.set(null);
        this.panelError.set(null);
        this.formError.set(null);
        this.refusal.set(null);
        this.confirming.set(null);
        this.pairAdded.set(null);
        this.pairRemoved.set(null);
        this.loadPreview(null, true);
        this.loadVersion();
    }

    isOpen(slug: string, ordinal: number): boolean {
        const selected = this.selected();
        return selected?.slug === slug && selected.ordinal === ordinal;
    }

    /**
     * Another sheet: its cells, and — on a draft being confirmed — the layout's sheet with it. The
     * rest of what the reader typed stays: they are choosing where the checklist is, not starting over.
     */
    showSheet(sheet: string): void {
        this.layoutDraft.update((draft) => (draft ? { ...draft, sheet } : draft));
        this.loadPreview(sheet, false);
    }

    /** Everything the panel shows, read again — what a refusal for a changed draft asks for. */
    reloadShown(): void {
        const selected = this.selected();
        if (selected) this.open(selected.slug, selected.ordinal);
        this.refreshTemplate();
    }

    private loadPreview(sheet: string | null, resetDraft: boolean): void {
        const selected = this.selected();
        if (!selected) return;
        this.previewLoading.set(true);
        this.previewRequest.run(this.api.checklistPreview(selected.slug, selected.ordinal, sheet), {
            next: (preview) => {
                this.preview.set(preview);
                this.previewLoading.set(false);
                if (resetDraft || !this.layoutDraft()) this.layoutDraft.set(draftFrom(preview));
            },
            error: (failure) => {
                this.previewLoading.set(false);
                this.panelError.set(messageOf(failure, this.i18n.t('checklist_templates.error_preview')));
            }
        });
    }

    private loadVersion(): void {
        const selected = this.selected();
        if (!selected) return;
        this.versionRequest.run(this.api.checklistVersion(selected.slug, selected.ordinal), {
            next: (version) => this.version.set(version),
            error: (failure) =>
                this.panelError.set(messageOf(failure, this.i18n.t('checklist_templates.error_preview')))
        });
    }

    /** The template's row in the list, read again after a write changed one of its versions. */
    private refreshTemplate(): void {
        const selected = this.selected();
        if (!selected) return;
        this.api.checklistTemplate(selected.slug).subscribe({
            next: (template) =>
                this.templates.update((templates) =>
                    templates.some((one) => one.slug === template.slug)
                        ? templates.map((one) => (one.slug === template.slug ? template : one))
                        : [...templates, template]
                ),
            error: () => this.reload()
        });
    }

    // ------------------------------------------------------------------ the layout

    setColumn(column: ChecklistColumn, letters: string): void {
        this.layoutDraft.update((draft) =>
            draft ? { ...draft, columns: { ...draft.columns, [column]: letters } } : draft
        );
    }

    setHeader(field: ChecklistHeaderField, which: 'label' | 'value', ref: string): void {
        this.layoutDraft.update((draft) =>
            draft ? { ...draft, header: { ...draft.header, [field]: { ...draft.header[field], [which]: ref } } } : draft
        );
    }

    setDraft(
        patch: Partial<
            Pick<LayoutDraft, 'firstItemRow' | 'lastItemRow' | 'yes' | 'no' | 'offersNotApplicable' | 'notApplicable'>
        >
    ): void {
        this.layoutDraft.update((draft) => (draft ? { ...draft, ...patch } : draft));
    }

    /** The grid's cell styling: the item rows of the named columns, and the header cells. */
    cellClass(row: number, letters: string): string {
        const draft = this.layoutDraft();
        const ref = `${letters}${row}`;
        if (this.headerCells().has(ref)) return 'bg-amber-100 dark:bg-amber-900/40';
        const inItems =
            draft?.firstItemRow != null &&
            draft.lastItemRow != null &&
            row >= draft.firstItemRow &&
            row <= draft.lastItemRow;
        if (inItems && this.fieldsOfColumn().has(letters)) return 'bg-blue-100 dark:bg-blue-950/40';
        return '';
    }

    isColumnHeaderRow(row: number): boolean {
        return this.preview()?.proposal.columnHeaderRow === row;
    }

    isItemRow(row: number): boolean {
        const draft = this.layoutDraft();
        return (
            draft?.firstItemRow != null &&
            draft.lastItemRow != null &&
            row >= draft.firstItemRow &&
            row <= draft.lastItemRow
        );
    }

    /** "C · control", or the letters alone for a column the layout does not name. */
    columnHead(letters: string): string {
        const fields = this.fieldsOfColumn().get(letters);
        return fields ? `${letters} · ${fields.map((field) => this.columnLabel(field)).join(', ')}` : letters;
    }

    confirmLayout(): void {
        const draft = this.layoutDraft();
        const selected = this.selected();
        const shown = this.shown();
        if (!draft || !selected || !shown) return;
        const problem = layoutProblem(draft);
        if (problem) {
            this.formError.set(this.i18n.t(PROBLEM_KEYS[problem]));
            return;
        }
        const hadPairs = (this.version()?.pairs.length ?? 0) > 0;
        this.formError.set(null);
        this.refusal.set(null);
        this.busy.set(true);
        this.api.confirmChecklistLayout(selected.slug, selected.ordinal, shown.revision, layoutOf(draft)).subscribe({
            next: (version) => {
                this.busy.set(false);
                const count = version.items.length;
                // Each key spelt in its own call, so that the i18n check counts both.
                this.notice.set(
                    hadPairs
                        ? this.i18n.t('checklist_templates.layout_confirmed_unpaired', { count })
                        : this.i18n.t('checklist_templates.layout_confirmed', { count })
                );
                this.afterWrite(version);
            },
            error: (failure) => {
                this.busy.set(false);
                if (!this.refuse(failure, 'edit', shown.revision)) {
                    this.formError.set(messageOf(failure, this.i18n.t('checklist_templates.error_layout')));
                }
            }
        });
    }

    // ------------------------------------------------------------------ the pairing

    /** The pairs the draft has, plus the one chosen: the route replaces the list whole. */
    pair(): void {
        const added = this.pairAdded();
        const removed = this.pairRemoved();
        if (!added || !removed) return;
        this.sendPairs([...(this.version()?.pairs ?? []), { added, removed }]);
    }

    /** A pair made by hand, undone: the list without it. */
    unpair(change: ChecklistPairingChange): void {
        this.sendPairs((this.version()?.pairs ?? []).filter((pair) => pair.added !== change.readKey));
    }

    private sendPairs(pairs: ChecklistItemPair[]): void {
        const selected = this.selected();
        const shown = this.shown();
        if (!selected || !shown) return;
        this.busy.set(true);
        this.panelError.set(null);
        this.refusal.set(null);
        this.api.pairChecklistItems(selected.slug, selected.ordinal, shown.revision, pairs).subscribe({
            next: (version) => {
                this.busy.set(false);
                this.pairAdded.set(null);
                this.pairRemoved.set(null);
                this.afterWrite(version);
            },
            error: (failure) => {
                this.busy.set(false);
                if (!this.refuse(failure, 'edit', shown.revision)) {
                    this.panelError.set(messageOf(failure, this.i18n.t('checklist_templates.error_pairs')));
                }
            }
        });
    }

    // ------------------------------------------------------------------ derive, publish, retire

    derive(): void {
        const selected = this.selected();
        if (!selected) return;
        this.busy.set(true);
        this.panelError.set(null);
        this.refusal.set(null);
        this.api.deriveChecklistVersion(selected.slug, selected.ordinal, this.deriveLabel()).subscribe({
            next: (derived) => {
                this.busy.set(false);
                this.deriveLabel.set('');
                this.notice.set(
                    this.i18n.t('checklist_templates.derived_notice', {
                        ordinal: derived.version.ordinal,
                        from: selected.ordinal
                    })
                );
                this.open(derived.templateSlug, derived.version.ordinal);
                this.refreshTemplate();
            },
            error: (failure) => {
                this.busy.set(false);
                if (!this.refuse(failure, 'edit', this.shown()?.revision ?? 0)) {
                    this.panelError.set(messageOf(failure, this.i18n.t('checklist_templates.error_derive')));
                }
            }
        });
    }

    /**
     * Publishes **the revision on screen** — the one whose cells, layout and pairing the reader has
     * in front of them. Sending the latest revision instead, read afresh, would publish whatever an
     * author changed a second ago: the check the server makes would be defeated by the client.
     */
    publish(): void {
        const selected = this.selected();
        const shown = this.shown();
        if (!selected || !shown) return;
        const revision = shown.revision;
        this.act('publish', this.api.publishChecklistVersion(selected.slug, selected.ordinal, revision), revision);
    }

    retire(): void {
        const selected = this.selected();
        const shown = this.shown();
        if (!selected || !shown) return;
        this.act('retire', this.api.retireChecklistVersion(selected.slug, selected.ordinal), shown.revision);
    }

    private act(act: 'publish' | 'retire', request: Observable<ChecklistVersion>, revision: number): void {
        const wasDraft = this.shown()?.status === 'draft';
        this.busy.set(true);
        this.confirming.set(null);
        this.refusal.set(null);
        this.panelError.set(null);
        request.subscribe({
            next: (version) => {
                this.busy.set(false);
                const ordinal = version.version.ordinal;
                this.notice.set(
                    act === 'publish'
                        ? this.i18n.t('checklist_templates.published_notice', { ordinal })
                        : wasDraft
                          ? this.i18n.t('checklist_templates.set_aside_notice', { ordinal })
                          : this.i18n.t('checklist_templates.retired_notice', { ordinal })
                );
                this.afterWrite(version);
            },
            error: (failure) => {
                this.busy.set(false);
                if (!this.refuse(failure, act, revision)) {
                    this.panelError.set(messageOf(failure, this.i18n.t('checklist_templates.error_act')));
                }
            }
        });
    }

    /**
     * A refusal whose problem type names its cause, explained in the panel — the panel keeps what the
     * reader reviewed rather than replacing it with what somebody changed meanwhile. `false` for any
     * other failure, which the caller shows in the server's own words.
     */
    private refuse(failure: unknown, act: 'publish' | 'retire' | 'edit', revision: number): boolean {
        const cause = conflictOf(failure);
        if (!cause) return false;
        const refusal: Refusal =
            cause === 'four_eyes' ? (act === 'retire' ? 'four_eyes_retire' : 'four_eyes_publish') : cause;
        this.refusal.set({
            message: this.i18n.t(REFUSAL_KEYS[refusal], {
                revision,
                authors: (this.shown()?.draftAuthors ?? []).join(', ')
            }),
            reload: REFUSAL_RELOADS[refusal]
        });
        return true;
    }

    /** A write answered with the version: shown, its preview and its template's row read again. */
    private afterWrite(version: ChecklistVersion): void {
        this.version.set(version);
        this.loadPreview(this.layoutDraft()?.sheet ?? null, true);
        this.loadVersion();
        this.refreshTemplate();
    }
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

/** The cause a template refusal names in its problem type, or `null` for any other failure. */
export function conflictOf(failure: unknown): TemplateConflict | null {
    const type = (failure as { error?: { type?: unknown } } | null)?.error?.type;
    return typeof type === 'string' ? (CONFLICT_TYPES[type] ?? null) : null;
}
