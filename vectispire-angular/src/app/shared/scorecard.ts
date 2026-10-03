import { ChangeDetectionStrategy, Component, computed, inject, input } from '@angular/core';
import { TagModule } from '@openng/optimus-ui/tag';
import { TranslatePipe } from '../core/i18n/translate.pipe';
import { GradeLabelPipe } from './grade-label';
import { riskPointsLabel } from './risk-points';
import { I18nService } from '../core/i18n/i18n.service';
import type { SecurityScorecard } from '../core/api.models';

export function gradeSeverity(grade?: string): 'success' | 'warn' | 'danger' | 'secondary' {
    switch (grade) {
        case 'A_PLUS':
        case 'A':
            return 'success';
        case 'B':
        case 'C':
            return 'warn';
        case 'D':
        case 'F':
            return 'danger';
        default:
            return 'secondary';
    }
}

/**
 * A security scorecard: the score and its grade, the counts it was computed from, the server's
 * recommendations. Whatever a page adds about the card — a repository's badge — is projected between
 * the counts and the recommendations.
 *
 * **No data replaces the score, not the counts.** The server grades `NO_DATA`, with a null score,
 * when nothing in the card's scope holds a completed scan — it used to answer 100/100, A+, for a
 * scope nobody had scanned, and this page read the compliance summary's `observedTargets` to hide it.
 * The flag is the card's own now, so the repository dialog and a project's page draw the same dash
 * from the same answer, as the compliance verdicts do; the counts stay, being true of what was read.
 *
 * **The risk points sit under the score** (decision 0036): the weighted open backlog it is computed
 * from. Deep in F the score is held at one, and the points are what still moves when a team fixes
 * something. They go with the score — absent with no data. **A project's or a solution's card names
 * its weakest target**, the one its grade is read from: a scope is graded by its most exposed target,
 * and a grade with no target named sends the reader looking through every one of them.
 */
@Component({
    selector: 'app-scorecard',
    imports: [TagModule, TranslatePipe, GradeLabelPipe],
    changeDetection: ChangeDetectionStrategy.Eager,
    template: `
        <div class="flex flex-col gap-4" data-testid="scorecard">
            <div
                class="flex items-center justify-between p-4 rounded-xl bg-surface-50 dark:bg-surface-800 border border-surface-200 dark:border-surface-700"
            >
                <div>
                    <div class="text-sm text-surface-500 font-medium uppercase">
                        {{ 'repositories.posture_grade' | translate }}
                    </div>
                    <div class="text-2xl font-bold mt-1">{{ card().targetName }}</div>
                </div>
                <div class="flex items-center gap-3">
                    @if (noData()) {
                        <div class="text-3xl font-extrabold" data-testid="scorecard-score">—</div>
                        <p-tag
                            severity="secondary"
                            data-testid="scorecard-grade"
                            [value]="'NO_DATA' | gradeLabel"
                            styleClass="text-lg font-bold px-3 py-1"
                        />
                    } @else {
                        <div class="text-3xl font-extrabold" data-testid="scorecard-score">
                            {{ card().score }}<span class="text-lg text-surface-400 font-normal">/100</span>
                        </div>
                        <p-tag
                            data-testid="scorecard-grade"
                            [severity]="severityOf(card().grade)"
                            [value]="card().grade | gradeLabel"
                            styleClass="text-lg font-bold px-3 py-1"
                        />
                    }
                </div>
            </div>

            @if (riskPoints(); as points) {
                <p class="m-0 text-sm text-muted-color" data-testid="scorecard-risk-points">
                    <span class="font-semibold text-color">{{ points }}</span>
                    — {{ 'repositories.risk_points_help' | translate }}
                </p>
            }
            @if (!noData() && card().weakestTarget; as weakest) {
                <p class="m-0 text-sm" data-testid="scorecard-weakest">
                    {{ 'repositories.weakest_target' | translate: { name: weakest.targetName } }}
                    <p-tag [severity]="severityOf(weakest.grade)" [value]="weakest.grade | gradeLabel" />
                    <span class="font-mono">{{ weakest.score }}/100</span>
                </p>
            }

            <div class="grid grid-cols-2 sm:grid-cols-4 gap-2 text-center">
                <div class="p-2 border rounded bg-surface-0 dark:bg-surface-900">
                    <div class="text-xs text-surface-500 uppercase font-semibold">
                        {{ 'repositories.kpi_kev' | translate }}
                    </div>
                    <div class="text-lg font-bold text-red-600">{{ card().openKevCount }}</div>
                </div>
                <div class="p-2 border rounded bg-surface-0 dark:bg-surface-900">
                    <div class="text-xs text-surface-500 uppercase font-semibold">
                        {{ 'repositories.kpi_critical' | translate }}
                    </div>
                    <div class="text-lg font-bold text-red-500">{{ card().openCriticalCount }}</div>
                </div>
                <div class="p-2 border rounded bg-surface-0 dark:bg-surface-900">
                    <div class="text-xs text-surface-500 uppercase font-semibold">
                        {{ 'repositories.kpi_high' | translate }}
                    </div>
                    <div class="text-lg font-bold text-amber-500">{{ card().openHighCount }}</div>
                </div>
                <div class="p-2 border rounded bg-surface-0 dark:bg-surface-900">
                    <div class="text-xs text-surface-500 uppercase font-semibold">
                        {{ 'repositories.kpi_licenses' | translate }}
                    </div>
                    <div class="text-lg font-bold text-purple-500">{{ card().licenseViolationCount }}</div>
                </div>
            </div>

            <ng-content />

            @if (card().recommendations.length > 0) {
                <div class="flex flex-col gap-2">
                    <span class="text-sm font-semibold">{{ 'repositories.recommendations' | translate }}</span>
                    <ul class="m-0 pl-4 text-sm text-surface-600 dark:text-surface-400 space-y-1">
                        @for (rec of card().recommendations; track rec) {
                            <li>{{ rec }}</li>
                        }
                    </ul>
                </div>
            }
        </div>
    `
})
export class ScorecardView {
    readonly card = input.required<SecurityScorecard>();
    readonly noData = computed(() => this.card().grade === 'NO_DATA' || this.card().score === null);

    private readonly i18n = inject(I18nService);

    /** In words, or null with no grade: the points go with the score. Zero is "0 risk points", shown. */
    readonly riskPoints = computed(() => {
        this.i18n.translations();
        const points = this.card().riskPoints;
        return this.noData() || points === null ? null : riskPointsLabel(points, this.i18n);
    });

    readonly severityOf = gradeSeverity;
}
