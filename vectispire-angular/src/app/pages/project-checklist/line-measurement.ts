import { DatePipe } from '@angular/common';
import { ChangeDetectionStrategy, Component, computed, inject, input, output, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { ButtonModule } from '@openng/optimus-ui/button';
import { TagModule } from '@openng/optimus-ui/tag';
import type { ChecklistRule, MeasuredLine, RepositoryLook } from '../../core/api.models';
import { I18nService } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { describeRule, ruleKindLabel, scopeLabel, severityLabel } from '../../shared/checklist-rules';
import {
    differs,
    LOOK_STATUS_KEYS,
    MEASURED_PROBLEM_KEYS,
    NO_DATA_KEYS,
    NO_DATA_SHORT_KEYS,
    oneClickAnswer,
    OUTCOME_KEYS,
    RECONCILIATION_KEYS,
    RECONCILIATION_SEVERITIES,
    SOURCE_KEYS
} from './measurements';

/**
 * What a rule found for one checklist line, beside its answer (decision 0032 §6).
 *
 * **Vectispire never answers.** The measurement is evidence shown to a person; the one click it offers
 * sends that person's answer, resting on the measurement they read — named by its evidence digest, so
 * that the server refuses it if the evidence moved in between.
 *
 * **No data is never a pass, and it says why** in the reader's words: every reason the server names is
 * one sentence here. The per-repository `detail` and the figures' are the server's English, shown as it
 * wrote them, like any other data.
 */
@Component({
    selector: 'app-line-measurement',
    imports: [DatePipe, RouterLink, ButtonModule, TagModule, TranslatePipe],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './line-measurement.html'
})
export class LineMeasurement {
    private readonly i18n = inject(I18nService);

    /** The line's rule, from the checklist view — shown before its measurement is read. */
    readonly rule = input.required<ChecklistRule>();
    readonly position = input.required<number>();
    /** The line as the measurements route answered; null while it is read, or when it failed. */
    readonly measured = input<MeasuredLine | null>(null);
    /**
     * The line's problems as the checklist view counts them. On a draft they include the measurement's
     * own (`measurement_contradicted`, and a yes without data wanting its comment or proof): a badge
     * naming one of those again would show the same obstacle twice.
     */
    readonly lineProblems = input<readonly string[]>([]);
    /** Computed for this read (a draft, a submitted revision) rather than frozen by the sign-off. */
    readonly live = input(false);
    /** Whether the person may answer the line now: the newest draft, a role that writes. */
    readonly answerable = input(false);
    readonly busy = input(false);

    /** "Answer as measured" — the page sends it, or opens the form it needs. */
    readonly answerAsMeasured = output<void>();

    readonly evidenceOpen = signal(false);

    readonly found = computed(() => this.measured()?.measurement ?? null);
    readonly offered = computed(() => oneClickAnswer(this.measured(), this.live(), this.answerable()));
    /** What the measurement keeps from a submission that the line's own problems do not already say. */
    readonly measuredProblems = computed(() => {
        const said = new Set(this.lineProblems());
        return (this.measured()?.problems ?? []).filter((problem) => !said.has(problem));
    });
    readonly changedSinceSubmission = computed(() => {
        const line = this.measured();
        return !!line && differs(line);
    });

    ruleKind(): string {
        return ruleKindLabel(this.i18n, this.rule().kind);
    }

    ruleWords(): string[] {
        return describeRule(this.i18n, this.rule());
    }

    outcomeLabel(outcome: string): string {
        return this.label(OUTCOME_KEYS, outcome);
    }

    outcomeSeverity(outcome: string): 'success' | 'danger' | 'warn' {
        return outcome === 'pass' ? 'success' : outcome === 'fail' ? 'danger' : 'warn';
    }

    reasonSentence(reason: string): string {
        return this.label(NO_DATA_KEYS, reason);
    }

    reasonShort(reason: string): string {
        return this.label(NO_DATA_SHORT_KEYS, reason);
    }

    reconciliationLabel(reconciliation: string): string {
        return this.label(RECONCILIATION_KEYS, reconciliation);
    }

    reconciliationSeverity(reconciliation: string): 'success' | 'danger' | 'warn' | 'info' | 'secondary' {
        return (
            (RECONCILIATION_SEVERITIES as Record<string, 'success' | 'danger' | 'warn' | 'info' | 'secondary'>)[
                reconciliation
            ] ?? 'secondary'
        );
    }

    problemLabel(problem: string): string {
        return this.label(MEASURED_PROBLEM_KEYS, problem);
    }

    /** The repository by its name, as every screen names it; by its id once it left the project or is gone. */
    repositoryLabel(look: RepositoryLook): string {
        this.i18n.translations();
        return look.repositoryName ?? this.i18n.t('project_checklist.repository_n', { id: look.repositoryId });
    }

    statusLabel(status: string): string {
        return this.label(LOOK_STATUS_KEYS, status);
    }

    sourceLabel(look: RepositoryLook): string {
        this.i18n.translations();
        const key = look.source ? (SOURCE_KEYS as Record<string, string | undefined>)[look.source] : undefined;
        return key ? this.i18n.t(key, { id: look.sourceId ?? '' }) : (look.source ?? '—');
    }

    scopeLabel(scope: string): string {
        return scopeLabel(this.i18n, scope);
    }

    severityLabel(severity: string): string {
        return severityLabel(this.i18n, severity);
    }

    metLabel(met: boolean | null): string {
        this.i18n.translations();
        return met === null ? '—' : met ? this.i18n.t(OUTCOME_KEYS.pass) : this.i18n.t(OUTCOME_KEYS.fail);
    }

    private label(keys: Readonly<Record<string, string>>, value: string): string {
        this.i18n.translations();
        const key = keys[value];
        return key ? this.i18n.t(key) : value;
    }
}
