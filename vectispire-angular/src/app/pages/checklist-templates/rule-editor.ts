import { CommonModule } from '@angular/common';
import { ChangeDetectionStrategy, Component, computed, inject, input, OnInit, output, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from '@openng/optimus-ui/button';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import type { ChecklistItem, ChecklistRule, ChecklistRuleKind, ChecklistSeverity } from '../../core/api.models';
import { I18nService } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import {
    AGGREGATION_KEYS,
    AGGREGATIONS,
    BUILT_IN_SCOPES,
    type ComponentDraft,
    type CoverageAggregation,
    type CoverageMetric,
    describeRule,
    draftOf,
    METRIC_KEYS,
    METRICS,
    normalizedScope,
    refusalMessage,
    RULE_BOUNDS,
    RULE_KINDS,
    ruleKindLabel,
    ruleOf,
    ruleRefusal,
    type RuleDraft,
    scopeLabel,
    secretsAtZero,
    SEVERITIES,
    severityLabel,
    emptyDraft,
    type ThresholdDraft
} from '../../shared/checklist-rules';

/**
 * The rule one template line is measured by, as a security lead binds it on a draft (decision 0032 §6).
 *
 * **The KPI's text sits beside the parameters, and the rule in words beside both** (§3, step 4): the
 * KPI stays the template's sentence, nothing is read out of it, and the person binding the thresholds
 * is the one who sees whether the two say the same thing — "no critical, at most two high" against a
 * rule that allows five.
 *
 * Nothing is sent from here: the rule kept goes back to the page, which sends the lines changed
 * together, on the revision on screen, as it does the evidence requirements.
 */
@Component({
    selector: 'app-checklist-rule-editor',
    standalone: true,
    imports: [CommonModule, FormsModule, ButtonModule, InputTextModule, MessageModule, TranslatePipe],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './rule-editor.html'
})
export class ChecklistRuleEditor implements OnInit {
    private readonly i18n = inject(I18nService);

    /** The line being bound. */
    readonly item = input.required<ChecklistItem>();
    /** Its rule as the page holds it — the version's, or one kept and not saved yet; null for none. */
    readonly rule = input<ChecklistRule | null>(null);
    /** The scopes the organisation's plugins and declared sources offer, suggested as the lead types. */
    readonly suggestions = input<string[]>([]);

    /** The rule kept, or `null` for "measured by no rule". */
    readonly kept = output<ChecklistRule | null>();
    readonly cancelled = output<void>();

    readonly kinds = RULE_KINDS;
    readonly severities = SEVERITIES;
    readonly builtIns = BUILT_IN_SCOPES;
    readonly metrics = METRICS;
    readonly aggregations = AGGREGATIONS;
    readonly bounds = RULE_BOUNDS;

    readonly draft = signal<RuleDraft>(emptyDraft(null));
    readonly otherScope = signal('');
    readonly error = signal<string | null>(null);

    /** The scopes other than a built-in step: a plugin or an imported tool, typed or suggested. */
    readonly otherScopes = computed(() =>
        this.draft().scopes.filter((scope) => !(BUILT_IN_SCOPES as readonly string[]).includes(scope))
    );
    /** The rule in words while the form holds one the server would take; null otherwise. */
    readonly described = computed(() => {
        const draft = this.draft();
        if (!draft.kind || ruleRefusal(draft)) return null;
        const rule = ruleOf(draft);
        return rule ? describeRule(this.i18n, rule) : null;
    });

    ngOnInit(): void {
        this.draft.set(draftOf(this.rule()));
    }

    kindLabel(kind: string): string {
        return ruleKindLabel(this.i18n, kind);
    }

    severityLabel(severity: string): string {
        return severityLabel(this.i18n, severity);
    }

    scopeLabel(scope: string): string {
        return scopeLabel(this.i18n, scope);
    }

    metricLabel(metric: CoverageMetric): string {
        this.i18n.translations();
        return this.i18n.t(METRIC_KEYS[metric]);
    }

    aggregationLabel(aggregation: CoverageAggregation): string {
        this.i18n.translations();
        return this.i18n.t(AGGREGATION_KEYS[aggregation]);
    }

    /**
     * Another kind starts from nothing but the proposed age: the parameters of one kind are refused by
     * another, and carrying them over would carry a threshold nobody stated for this one.
     */
    setKind(kind: ChecklistRuleKind | null): void {
        this.error.set(null);
        const current = this.draft();
        const next = emptyDraft(kind);
        if (kind && current.kind && current.maxAgeDays !== null) next.maxAgeDays = current.maxAgeDays;
        this.draft.set(next);
    }

    patch(changes: Partial<RuleDraft>): void {
        this.error.set(null);
        this.draft.update((draft) => ({ ...draft, ...changes }));
    }

    setThreshold(severity: ChecklistSeverity, changes: Partial<ThresholdDraft>): void {
        this.error.set(null);
        this.draft.update((draft) => ({
            ...draft,
            thresholds: { ...draft.thresholds, [severity]: { ...draft.thresholds[severity], ...changes } }
        }));
    }

    hasScope(scope: string): boolean {
        return this.draft().scopes.includes(scope);
    }

    toggleScope(scope: string, on: boolean): void {
        this.patch({
            scopes: on
                ? [...this.draft().scopes.filter((one) => one !== scope), scope]
                : this.draft().scopes.filter((one) => one !== scope)
        });
    }

    /** A plugin or an imported tool, as typed; the form refuses a malformed one when the rule is kept. */
    addOtherScope(): void {
        const scope = normalizedScope(this.otherScope());
        if (!scope) return;
        this.toggleScope(scope, true);
        this.otherScope.set('');
    }

    removeScope(scope: string): void {
        this.toggleScope(scope, false);
    }

    addComponent(): void {
        this.patch({ components: [...this.draft().components, { purlPrefix: '', versions: '' }] });
    }

    setComponent(index: number, changes: Partial<ComponentDraft>): void {
        this.patch({
            components: this.draft().components.map((component, at) =>
                at === index ? { ...component, ...changes } : component
            )
        });
    }

    removeComponent(index: number): void {
        this.patch({ components: this.draft().components.filter((_, at) => at !== index) });
    }

    /** "No plaintext secret in configuration" (§6): the secret step, critical and high at zero, seven days. */
    presetSecrets(): void {
        this.error.set(null);
        this.draft.set(secretsAtZero());
    }

    /** Refused here as the server would, in the reader's words; kept otherwise, for the page to send. */
    keep(): void {
        const draft = this.draft();
        const refusal = ruleRefusal(draft);
        if (refusal) {
            this.error.set(refusalMessage(this.i18n, refusal));
            return;
        }
        this.error.set(null);
        this.kept.emit(ruleOf(draft));
    }

    unbind(): void {
        this.error.set(null);
        this.kept.emit(null);
    }
}
