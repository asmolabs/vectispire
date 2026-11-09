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

    readonly ruleKind = computed(() => ruleKindLabel(this.i18n, this.rule().kind));
    readonly ruleWords = computed(() => describeRule(this.i18n, this.rule()));

    /**
     * The measurement with every word and tone it shows worked out once per measurement or language,
     * the figures' and the repositories' rows included — not by a method per cell on every pass.
     */
    readonly view = computed(() => {
        const found = this.found();
        if (!found) return null;
        const then = this.measured()?.atSubmission;
        return {
            ...found,
            outcomeTag: { severity: outcomeSeverity(found.outcome), label: this.label(OUTCOME_KEYS, found.outcome) },
            reasonSentence: found.reason ? this.label(NO_DATA_KEYS, found.reason) : null,
            outcomeAtSubmission: then ? this.label(OUTCOME_KEYS, then.outcome) : null,
            figureRows: found.evidence.figures.map((figure) => ({
                ...figure,
                scopeLabel: scopeLabel(this.i18n, figure.scope),
                severityLabel: severityLabel(this.i18n, figure.severity),
                metLabel: this.metLabel(figure.met)
            })),
            repositoryRows: found.evidence.repositories.map((look) => ({
                ...look,
                label: this.repositoryLabel(look),
                scopeLabel: look.scope ? scopeLabel(this.i18n, look.scope) : '—',
                statusLabel: this.label(LOOK_STATUS_KEYS, look.status),
                sourceLabel: this.sourceLabel(look),
                metLabel: this.metLabel(look.met)
            }))
        };
    });

    /** How the answer and the measurement agree, as its tag says it. */
    readonly reconciliation = computed(() => {
        const line = this.measured();
        if (!line) return null;
        return {
            severity:
                (RECONCILIATION_SEVERITIES as Record<string, 'success' | 'danger' | 'warn' | 'info' | 'secondary'>)[
                    line.reconciliation
                ] ?? 'secondary',
            label: this.label(RECONCILIATION_KEYS, line.reconciliation)
        };
    });

    readonly problemBadges = computed(() =>
        this.measuredProblems().map((problem) => ({ problem, label: this.label(MEASURED_PROBLEM_KEYS, problem) }))
    );

    /** The repository by its name, as every screen names it; by its id once it left the project or is gone. */
    private repositoryLabel(look: RepositoryLook): string {
        return look.repositoryName ?? this.i18n.t('project_checklist.repository_n', { id: look.repositoryId });
    }

    private sourceLabel(look: RepositoryLook): string {
        const key = look.source ? (SOURCE_KEYS as Record<string, string | undefined>)[look.source] : undefined;
        return key ? this.i18n.t(key, { id: look.sourceId ?? '' }) : (look.source ?? '—');
    }

    private metLabel(met: boolean | null): string {
        return met === null ? '—' : met ? this.i18n.t(OUTCOME_KEYS.pass) : this.i18n.t(OUTCOME_KEYS.fail);
    }

    private label(keys: Readonly<Record<string, string>>, value: string): string {
        const key = keys[value];
        return key ? this.i18n.t(key) : value;
    }
}

function outcomeSeverity(outcome: string): 'success' | 'danger' | 'warn' {
    return outcome === 'pass' ? 'success' : outcome === 'fail' ? 'danger' : 'warn';
}
