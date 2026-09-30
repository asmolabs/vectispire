import { ChangeDetectionStrategy, Component, input } from '@angular/core';
import { TagModule } from '@openng/optimus-ui/tag';
import { TranslatePipe } from '../core/i18n/translate.pipe';
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
 * **`noData` replaces the score, not the counts.** The scorecard starts at a hundred and subtracts
 * what it finds, so a scope where nothing was ever scanned scores high on nothing — the green that
 * should raise an alarm. Where the page knows nothing was observed, the score is a dash and says "No
 * data", as the compliance verdicts do; the zero counts stay, since they are true of what was read.
 */
@Component({
    selector: 'app-scorecard',
    standalone: true,
    imports: [TagModule, TranslatePipe],
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
                            [value]="'soa.measured.NO_DATA' | translate"
                            styleClass="text-lg font-bold px-3 py-1"
                        />
                    } @else {
                        <div class="text-3xl font-extrabold" data-testid="scorecard-score">
                            {{ card().score }}<span class="text-lg text-surface-400 font-normal">/100</span>
                        </div>
                        <p-tag
                            data-testid="scorecard-grade"
                            [severity]="severityOf(card().grade)"
                            [value]="'repositories.grade_tag' | translate: { grade: card().grade }"
                            styleClass="text-lg font-bold px-3 py-1"
                        />
                    }
                </div>
            </div>

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
    readonly noData = input(false);

    readonly severityOf = gradeSeverity;
}
