import { NgClass } from '@angular/common';
import { ChangeDetectionStrategy, Component, computed, inject, input, output, signal } from '@angular/core';
import { ButtonModule } from '@openng/optimus-ui/button';
import { TagModule } from '@openng/optimus-ui/tag';
import { TranslatePipe } from '../core/i18n/translate.pipe';
import { I18nService } from '../core/i18n/i18n.service';
import type { ComplianceEvaluation, ComplianceSummary } from '../core/api.models';
import {
    FRAMEWORKS,
    complianceStatusLabel,
    frameworkDescription,
    frameworkLabel,
    gateStatusLabel
} from './compliance-labels';
import { LocalNumberPipe } from '../core/i18n/local-number.pipe';
import { LocalPercentPipe } from '../core/i18n/local-percent.pipe';

/**
 * A `ComplianceSummary`, drawn: the executive figures, the per-target matrix, the frameworks and the
 * controls of the one selected.
 *
 * **One drawing for every scope.** The estate, a project and a solution receive the same shape from
 * the server — a scope's summary is the estate's computed over the scope's targets — and a second
 * copy of this template would be a second answer to "how does a verdict read", which would drift
 * from the first on the first change, `NO_DATA` first of all.
 */
@Component({
    selector: 'app-compliance-summary',
    imports: [NgClass, ButtonModule, TagModule, TranslatePipe, LocalNumberPipe, LocalPercentPipe],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './compliance-summary.html'
})
export class ComplianceSummaryView {
    private readonly i18n = inject(I18nService);

    readonly summary = input.required<ComplianceSummary>();
    /** The per-target matrix: the estate's global view and a scope's page show it, one target does not. */
    readonly showMatrix = input(true);
    /** Whether each matrix row offers to narrow the page to its target — only where the page can. */
    readonly inspectable = input(false);
    readonly inspect = output<string>();

    readonly selectedFramework = signal<string>('NIS_2');

    /**
     * The share of the scope observed inside the freshness window.
     *
     * **A hundred per cent on an empty scope, deliberately.** Zero would read as an alarm where there
     * is nothing to observe, and an alarm that fires on a fresh deployment teaches its reader to
     * ignore the one that matters.
     */
    readonly freshnessRate = computed(() => {
        const data = this.summary();
        if (data.totalMonitoredTargets === 0) {
            return 100;
        }
        return Math.round((data.freshTargets / data.totalMonitoredTargets) * 100);
    });

    /**
     * Targets for which no observation exists — not "stale", **absent**.
     *
     * A stale observation is dated: you know what you do not know. A target never scanned presents
     * no known vulnerability, which makes it green on any table that counts findings. This is the
     * figure that separates "clean" from "never looked at".
     */
    readonly neverObserved = computed(() => {
        const data = this.summary();
        return Math.max(0, data.totalMonitoredTargets - data.observedTargets);
    });

    /** Red as soon as one target has never been observed; orange below three quarters of the scope. */
    readonly freshnessTone = computed(() => {
        if (this.neverObserved() > 0) {
            return 'text-red-500';
        }
        return this.freshnessRate() < 75 ? 'text-orange-500' : 'text-green-500';
    });

    /** The share of the scope passing its gate; a hundred on an empty scope, like freshness. */
    readonly gatePassRate = computed(() => {
        const data = this.summary();
        return data.totalMonitoredTargets > 0
            ? Math.round((data.passingGateTargets / data.totalMonitoredTargets) * 100)
            : 100;
    });

    readonly orderedEvaluations = computed<ComplianceEvaluation[]>(() => {
        const orderMap = new Map<string, number>(FRAMEWORKS.map((key, i) => [key, i]));
        return [...this.summary().evaluations].sort((a, b) => {
            const orderA = orderMap.get(a.framework) ?? 99;
            const orderB = orderMap.get(b.framework) ?? 99;
            return orderA - orderB;
        });
    });

    readonly activeEvaluation = computed<ComplianceEvaluation | null>(
        () => this.summary().evaluations.find((e) => e.framework === this.selectedFramework()) ?? null
    );

    /**
     * The matrix's rows with the gate and the verdict in words and tones, worked out once per summary or
     * language — not by five methods per row on every pass. The gate showed `PASSED`, `NEVER_SCANNED` as
     * the server spells them.
     */
    readonly matrix = computed(() =>
        (this.summary().targets ?? []).map((target) => ({
            ...target,
            gateLabel: gateStatusLabel(this.i18n, target.gateStatus),
            gateSeverity: gateStatusSeverity(target.gateStatus),
            verdict: this.verdict(target.overallStatus, target.overallScore)
        }))
    );

    /** The framework cards, each with its name and what it covers read through the one map every screen uses. */
    readonly cards = computed(() =>
        this.orderedEvaluations().map((evaluation) => ({
            ...evaluation,
            name: frameworkLabel(this.i18n, evaluation.framework),
            description: frameworkDescription(this.i18n, evaluation.framework),
            verdict: this.verdict(evaluation.overallStatus, evaluation.scorePercentage)
        }))
    );

    /** The selected framework's breakdown, its controls' verdicts worked out with it. */
    readonly active = computed(() => {
        const evaluation = this.activeEvaluation();
        if (!evaluation) return null;
        return {
            ...evaluation,
            name: frameworkLabel(this.i18n, evaluation.framework),
            verdict: this.verdict(evaluation.overallStatus, evaluation.scorePercentage),
            controls: evaluation.controls.map((control) => ({
                ...control,
                verdict: this.verdict(control.status, control.scorePercentage)
            }))
        };
    });

    selectFramework(key: string): void {
        this.selectedFramework.set(key);
    }

    /**
     * A verdict as a tag and a figure: the status in the reader's language — one the client does not know
     * yet shown as sent — and the score, or a dash where nothing was measured: its zero is no measurement.
     */
    private verdict(
        status: string,
        score: number
    ): { label: string; severity: ReturnType<typeof statusSeverity>; score: string } {
        return {
            label: complianceStatusLabel(this.i18n, status),
            severity: statusSeverity(status),
            score: status === 'NO_DATA' ? '—' : this.i18n.percent(score)
        };
    }
}

export function statusSeverity(status: string): 'success' | 'warn' | 'danger' | 'secondary' {
    if (status === 'COMPLIANT') return 'success';
    if (status === 'PARTIAL') return 'warn';
    // No data is no verdict: neither green nor red.
    if (status === 'NO_DATA') return 'secondary';
    return 'danger';
}

function gateStatusSeverity(status: string): 'success' | 'info' | 'warn' | 'danger' {
    if (status === 'PASSED') return 'success';
    if (status === 'SCANNING' || status === 'IN_PROGRESS') return 'info';
    if (status === 'NEVER_SCANNED') return 'warn';
    return 'danger';
}
