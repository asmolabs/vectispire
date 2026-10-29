import { computed, effect, inject, Injectable, signal, untracked } from '@angular/core';
import { messageOf } from '../../core/api-error';
import { ChecklistsApi } from '../../core/api/checklists.api';
import { PluginsApi } from '../../core/api/plugins.api';
import { SarifApi } from '../../core/api/sarif.api';
import { SettingsApi } from '../../core/api/settings.api';
import type { ChecklistPreview, ChecklistRule, ChecklistTemplate, ChecklistVersion } from '../../core/api.models';
import { I18nService } from '../../core/i18n/i18n.service';
import { LatestRequest } from '../../core/latest-request';
import { SessionStore } from '../../core/session.store';
import { describeUnrenderableCells, unrenderableCellsOf } from '../../shared/unrenderable-cells';
import {
    conflictOf,
    draftFrom,
    EvidenceEdit,
    LayoutDraft,
    Refusal,
    REFUSAL_KEYS,
    REFUSAL_RELOADS,
    wrote
} from './templates-model';

/**
 * What the checklist templates screen shows, and what its parts share, provided by `ChecklistTemplates`
 * so each visit starts from nothing.
 *
 * **Never published in one step.** A workbook becomes a draft; the reader's proposal is shown on the
 * sheet's own cells, a person confirms or corrects each column letter, the item rows, the header
 * cells and the template's answer words; the items are paired with the previous version; then it is
 * published — naming the revision on screen, so that an edit made meanwhile refuses the publication
 * rather than publishing something nobody here has read.
 *
 * The version open below the list lives here, and so does everything opening another one resets —
 * the layout being typed, the requirements and rules changed and not sent, the pair being chosen —
 * so that one call clears it all. Every write answers the version, which {@link afterWrite} adopts;
 * a refusal whose problem type names its cause is explained by {@link refuse}, never from its English.
 */
@Injectable()
export class TemplatesPage {
    private readonly api = inject(ChecklistsApi);
    private readonly pluginsApi = inject(PluginsApi);
    private readonly sarifApi = inject(SarifApi);
    private readonly settingsApi = inject(SettingsApi);
    private readonly i18n = inject(I18nService);
    private readonly session = inject(SessionStore);
    // Two streams: switching sheets must not cancel the items, and an older preview must not land
    // over a newer one when the reader clicks through sheets faster than the server answers.
    private readonly previewRequest = new LatestRequest();
    private readonly versionRequest = new LatestRequest();

    /** The server's `@RequiresSecurityLead`: who is offered a write control. */
    readonly writes = this.session.isSecurityLead;

    readonly templates = signal<ChecklistTemplate[]>([]);
    readonly loading = signal(true);
    readonly error = signal<string | null>(null);
    readonly notice = signal<string | null>(null);

    // The import form's slug, name and error: the list's "new version" fills the first and clears the others.
    readonly uploadSlug = signal('');
    readonly uploadName = signal('');
    readonly uploadError = signal<string | null>(null);

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
    readonly pairAdded = signal<string | null>(null);
    readonly pairRemoved = signal<string | null>(null);
    /** The requirements changed on screen and not sent yet, by item key. */
    readonly evidenceEdits = signal<Record<string, EvidenceEdit>>({});
    readonly evidenceError = signal<string | null>(null);
    /** The rules kept on screen and not sent yet, by item key; `null` unbinds the line. */
    readonly ruleEdits = signal<Record<string, ChecklistRule | null>>({});
    /** The line whose rule the editor is open on, by key. */
    readonly editingRule = signal<string | null>(null);
    readonly rulesError = signal<string | null>(null);
    /**
     * The scopes a findings rule may name beyond the built-in steps: the registered plugins, and each
     * SARIF source's declared tools — read once, when an editor first opens, and suggestions only: a
     * scope is typed as well, since a plugin registered tomorrow is a rule a lead may bind today.
     */
    readonly scopeSuggestions = signal<string[] | null>(null);

    /** What the panel shows, and what publishing names: the preview's summary, read with the cells. */
    readonly shown = computed(() => this.preview()?.version ?? null);
    readonly editable = computed(() => this.writes() && this.shown()?.status === 'draft');
    /** The route's own conditions: a draft, a confirmed layout — its items exist only then — a security lead. */
    readonly evidenceEditable = computed(() => this.editable() && !!this.shown()?.layoutConfirmed);
    /** The same route conditions as the evidence requirements: a lead, a draft, a confirmed layout. */
    readonly rulesEditable = this.evidenceEditable;

    /** Whether the signed-in account is among the draft's authors — who, under four-eyes, may not publish it. */
    readonly wroteShown = computed(() => wrote(this.shown()?.draftAuthors ?? [], this.session.user()?.username));
    /**
     * `triage_four_eyes_required` as the settings catalog reads it — the setting that also governs a
     * template's publication. The version views do not carry it (a project checklist's view does), so
     * it is read from the catalog, once, and only when an author of the shown draft could be refused.
     * `null` until it is known, or when it could not be read: treated as on, the server's default.
     */
    readonly fourEyes = signal<boolean | null>(null);
    private fourEyesAsked = false;
    /**
     * Whether publishing the shown draft is withheld from the person on screen: four-eyes would
     * refuse them as one of its authors. The button used to stay enabled with an info message beside
     * it, and the click met a 409 the author had no way to act on.
     */
    readonly publishBlocked = computed(() => this.wroteShown() && this.fourEyes() !== false);

    constructor() {
        this.reload();
        effect(() => {
            if (this.editable() && this.wroteShown()) untracked(() => this.readFourEyes());
        });
    }

    private readFourEyes(): void {
        if (this.fourEyesAsked) return;
        this.fourEyesAsked = true;
        this.settingsApi.settings().subscribe({
            next: (result) => {
                const value = (result?.settings ?? []).find((one) => one.key === 'triage_four_eyes_required')?.value;
                this.fourEyes.set(value === 'true' ? true : value === 'false' ? false : null);
            },
            error: () => this.fourEyes.set(null)
        });
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
        this.evidenceEdits.set({});
        this.evidenceError.set(null);
        this.ruleEdits.set({});
        this.editingRule.set(null);
        this.rulesError.set(null);
        this.loadPreview(null, true);
        this.loadVersion();
    }

    /**
     * Another sheet: its cells, and — on a draft being confirmed — the layout's sheet with it. The
     * rest of what the reader typed stays: they are choosing where the checklist is, not starting over.
     */
    showSheet(sheet: string): void {
        this.layoutDraft.update((draft) => (draft ? { ...draft, sheet } : draft));
        this.loadPreview(sheet, false);
    }

    setDraft(
        patch: Partial<
            Pick<LayoutDraft, 'firstItemRow' | 'lastItemRow' | 'yes' | 'no' | 'offersNotApplicable' | 'notApplicable'>
        >
    ): void {
        this.layoutDraft.update((draft) => (draft ? { ...draft, ...patch } : draft));
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
    refreshTemplate(): void {
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

    /**
     * The plugins' ids and the SARIF sources' tools, as scopes. Either list failing leaves the other:
     * they are suggestions, and a lead who cannot read one still types the scope.
     */
    loadScopeSuggestions(): void {
        if (this.scopeSuggestions() !== null) return;
        this.scopeSuggestions.set([]);
        const add = (scopes: string[]) =>
            this.scopeSuggestions.update((known) => [...new Set([...(known ?? []), ...scopes])].sort());
        this.pluginsApi.plugins().subscribe({
            next: (plugins) => add(plugins.map((plugin) => `plugin:${plugin.id}`)),
            error: () => undefined
        });
        this.sarifApi.sarifSources().subscribe({
            next: (sources) =>
                add(
                    sources
                        .filter((source) => source.kinds.length === 0 || source.kinds.includes('sarif'))
                        .flatMap((source) =>
                            source.tools.map((tool) => `import:${source.slug}/${tool.trim().toLowerCase()}`)
                        )
                ),
            error: () => undefined
        });
    }

    // ------------------------------------------------------------------ writing

    /**
     * A refusal whose problem type names its cause, explained in the panel — the panel keeps what the
     * reader reviewed rather than replacing it with what somebody changed meanwhile. `false` for any
     * other failure, which the caller shows in the server's own words.
     */
    refuse(failure: unknown, act: 'publish' | 'retire' | 'edit', revision: number): boolean {
        const cause = conflictOf(failure);
        if (!cause) return false;
        if (cause === 'unrenderable') {
            const cells = unrenderableCellsOf(failure);
            // Refused for another reason than a formula — the server's words, rather than a sentence naming no cell.
            this.refusal.set({
                message: cells
                    ? this.i18n.t(REFUSAL_KEYS.unrenderable, { cells: describeUnrenderableCells(this.i18n, cells) })
                    : messageOf(failure, this.i18n.t('checklist_templates.error_act')),
                reload: REFUSAL_RELOADS.unrenderable
            });
            return true;
        }
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
    afterWrite(version: ChecklistVersion): void {
        this.version.set(version);
        // The summary the write answered is the one the next write names, before the preview lands.
        this.preview.update((preview) => (preview ? { ...preview, version: version.version } : preview));
        this.evidenceEdits.set({});
        this.ruleEdits.set({});
        this.editingRule.set(null);
        this.loadPreview(this.layoutDraft()?.sheet ?? null, true);
        this.loadVersion();
        this.refreshTemplate();
    }
}
