import { ChangeDetectionStrategy, Component, computed, inject } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from '@openng/optimus-ui/button';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import { messageOf } from '../../core/api-error';
import { ChecklistsApi } from '../../core/api/checklists.api';
import type { ChecklistEvidenceKind, ChecklistItem, ChecklistRule } from '../../core/api.models';
import { I18nService } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { describeRule, ruleKindLabel, sameRule } from '../../shared/checklist-rules';
import { ChecklistRuleEditor } from './rule-editor';
import {
    EVIDENCE_KINDS,
    EvidenceEdit,
    evidenceChangesOf,
    evidenceKindLabel,
    MAX_VALIDITY_MONTHS,
    MIN_VALIDITY_MONTHS,
    ruleChangesOf,
    validityAllowed
} from './templates-model';
import { TemplatesPage } from './templates-page';

/** One item of the version, with what the table shows of it worked out once. */
interface ItemRow {
    item: ChecklistItem;
    /** The line's requirement as the form shows it: the one changed on screen, else the version's. */
    requirement: EvidenceEdit;
    /** "None", or "File · 12 months": the requirement, read-only. */
    requirementText: string;
    /** The line's rule as the form shows it: the one kept on screen, else the version's. */
    rule: ChecklistRule | null;
    ruleKindText: string;
    ruleWords: string[];
    /** Whether the rule on screen is not the version's yet. */
    pending: boolean;
}

/**
 * The items the confirmed layout read, fill-down applied — what a project will answer — with the proof
 * each line asks for and the rule that measures it (decision 0032 §6), both edited on a draft by a
 * security lead and sent together, the lines changed only.
 *
 * The rows are computed when the version, an edit or the language changes, and tracked by item, so a
 * month being typed keeps its field rather than the row being drawn again under it.
 */
@Component({
    selector: 'app-template-items',
    imports: [
        FormsModule,
        ButtonModule,
        InputTextModule,
        MessageModule,
        TableModule,
        TagModule,
        TranslatePipe,
        ChecklistRuleEditor
    ],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './template-items.html'
})
export class TemplateItems {
    private readonly api = inject(ChecklistsApi);
    private readonly i18n = inject(I18nService);
    protected readonly page = inject(TemplatesPage);

    protected readonly minValidity = MIN_VALIDITY_MONTHS;
    protected readonly maxValidity = MAX_VALIDITY_MONTHS;
    protected readonly trackRow = (_index: number, row: ItemRow) => row.item.id;

    protected readonly kindOptions = computed(() =>
        EVIDENCE_KINDS.map((kind) => ({ value: kind, label: evidenceKindLabel(this.i18n, kind) }))
    );

    protected readonly rows = computed<ItemRow[]>(() => {
        const evidenceEdits = this.page.evidenceEdits();
        const ruleEdits = this.page.ruleEdits();
        return (this.page.version()?.items ?? []).map((item) => {
            const kind = evidenceKindLabel(this.i18n, item.evidenceKind);
            const rule = item.itemKey in ruleEdits ? ruleEdits[item.itemKey] : item.boundRule;
            return {
                item,
                requirement: evidenceEdits[item.itemKey] ?? {
                    kind: item.evidenceKind,
                    months: item.evidenceValidityMonths
                },
                requirementText:
                    item.evidenceKind !== 'none' && item.evidenceValidityMonths
                        ? `${kind} · ${this.i18n.t('checklist_templates.evidence_validity', { months: item.evidenceValidityMonths })}`
                        : kind,
                rule,
                ruleKindText: rule ? ruleKindLabel(this.i18n, rule.kind) : '',
                ruleWords: rule ? describeRule(this.i18n, rule) : [],
                pending: item.itemKey in ruleEdits && !sameRule(ruleEdits[item.itemKey], item.boundRule)
            };
        });
    });

    /** The line the editor is open on, as a list of one or none: the template tracks it by key. */
    protected readonly editingRows = computed(() =>
        this.rows().filter((row) => row.item.itemKey === this.page.editingRule())
    );
    /** The lines whose requirement the form changed, as the route reads them: only those are sent. */
    protected readonly evidenceChanges = computed(() =>
        evidenceChangesOf(this.page.version()?.items ?? [], this.page.evidenceEdits())
    );
    /** The lines whose rule the form changed, as the route reads them: only those are sent. */
    protected readonly ruleChanges = computed(() =>
        ruleChangesOf(this.page.version()?.items ?? [], this.page.ruleEdits())
    );

    private requirement(item: ChecklistItem): EvidenceEdit {
        return (
            this.page.evidenceEdits()[item.itemKey] ?? { kind: item.evidenceKind, months: item.evidenceValidityMonths }
        );
    }

    /** A line that asks for no proof has no validity either: the server refuses one, so the form drops it. */
    protected setEvidenceKind(item: ChecklistItem, kind: ChecklistEvidenceKind): void {
        const current = this.requirement(item);
        this.editEvidence(item, { kind, months: kind === 'none' ? null : current.months });
    }

    protected setEvidenceMonths(item: ChecklistItem, months: number | null): void {
        this.editEvidence(item, { ...this.requirement(item), months: months ?? null });
    }

    private editEvidence(item: ChecklistItem, edit: EvidenceEdit): void {
        this.page.evidenceError.set(null);
        this.page.evidenceEdits.update((edits) => ({ ...edits, [item.itemKey]: edit }));
    }

    /**
     * Sends the lines changed, and only those — the route is a partial update, and a line sent
     * unchanged would make its sender one of the draft's authors for nothing — on the revision on
     * screen, like a layout.
     */
    protected saveEvidence(): void {
        const selected = this.page.selected();
        const shown = this.page.shown();
        const changes = this.evidenceChanges();
        if (!selected || !shown || changes.length === 0) return;
        if (changes.some((change) => !validityAllowed(change))) {
            this.page.evidenceError.set(
                this.i18n.t('checklist_templates.problem_evidence_months', {
                    min: MIN_VALIDITY_MONTHS,
                    max: MAX_VALIDITY_MONTHS
                })
            );
            return;
        }
        this.page.busy.set(true);
        this.page.evidenceError.set(null);
        this.page.refusal.set(null);
        this.api.setChecklistEvidence(selected.slug, selected.ordinal, shown.revision, changes).subscribe({
            next: (version) => {
                this.page.busy.set(false);
                this.page.notice.set(this.i18n.t('checklist_templates.evidence_saved', { count: changes.length }));
                this.page.afterWrite(version);
            },
            error: (failure) => {
                this.page.busy.set(false);
                if (!this.page.refuse(failure, 'edit', shown.revision)) {
                    this.page.evidenceError.set(messageOf(failure, this.i18n.t('checklist_templates.error_evidence')));
                }
            }
        });
    }

    protected editRule(item: ChecklistItem): void {
        this.page.rulesError.set(null);
        this.page.editingRule.set(item.itemKey);
        this.page.loadScopeSuggestions();
    }

    /** A rule kept by the editor — or none — held on screen until the lines changed are saved together. */
    protected keepRule(item: ChecklistItem, rule: ChecklistRule | null): void {
        this.page.ruleEdits.update((edits) => ({ ...edits, [item.itemKey]: rule }));
        this.page.editingRule.set(null);
    }

    /** The line's rule back to the version's: nothing of it is sent. */
    protected undoRule(item: ChecklistItem): void {
        this.page.ruleEdits.update((edits) => {
            const rest = { ...edits };
            delete rest[item.itemKey];
            return rest;
        });
    }

    /**
     * Sends the lines whose rule changed, and only those — the route is a partial update, and a line
     * sent unchanged would make its sender one of the draft's authors for nothing — on the revision on
     * screen, like a layout. The version answered replaces the one shown.
     */
    protected saveRules(): void {
        const selected = this.page.selected();
        const shown = this.page.shown();
        const changes = this.ruleChanges();
        if (!selected || !shown || changes.length === 0) return;
        this.page.busy.set(true);
        this.page.rulesError.set(null);
        this.page.refusal.set(null);
        this.api.bindChecklistRules(selected.slug, selected.ordinal, shown.revision, changes).subscribe({
            next: (version) => {
                this.page.busy.set(false);
                this.page.notice.set(this.i18n.t('checklist_templates.rules_saved', { count: changes.length }));
                this.page.afterWrite(version);
            },
            error: (failure) => {
                this.page.busy.set(false);
                if (!this.page.refuse(failure, 'edit', shown.revision)) {
                    this.page.rulesError.set(messageOf(failure, this.i18n.t('checklist_templates.error_rules')));
                }
            }
        });
    }
}
