import { CommonModule } from '@angular/common';
import { Component, inject, signal, ChangeDetectionStrategy } from '@angular/core';
import { MessageModule } from '@openng/optimus-ui/message';
import { messageOf } from '@/app/core/api-error';
import { ComplianceApi } from '@/app/core/api/compliance.api';
import { I18nService } from '@/app/core/i18n/i18n.service';
import { TranslatePipe } from '@/app/core/i18n/translate.pipe';
import type { ComplianceMovement, ComplianceSeries, ComplianceStep } from '@/app/core/api.models';

/**
 * Each framework's progress, month by month.
 *
 * <p><b>A line on its own would mislead.</b> The score drops when one more repository is
 * registered, and when a detector is switched on: in both cases because the watch got wider. A
 * chart drawn without that reports "we regressed" in the month somebody started watching better,
 * and the team reading it learns to watch less.
 *
 * <p>Every month therefore carries its plausible cause, and a series whose estate changed is
 * announced <em>not comparable</em> rather than drawn as a trend.
 *
 * <p>Six frameworks, six series. No overall score: an aggregate number gets gamed — one improves
 * it by adding an easy framework, and a number one can improve without touching the estate is a
 * number somebody eventually improves that way.
 */
@Component({
    selector: 'zs-compliance-history',
    standalone: true,
    imports: [CommonModule, MessageModule, TranslatePipe],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './compliance-history.html'
})
export class ComplianceHistoryPage {
    private readonly complianceApi = inject(ComplianceApi);
    private readonly i18n = inject(I18nService);

    readonly series = signal<ComplianceSeries[]>([]);
    readonly error = signal<string | null>(null);

    constructor() {
        this.complianceApi.complianceHistory().subscribe({
            next: (data) => this.series.set(data),
            error: (failure) => this.error.set(messageOf(failure, this.i18n.t('history_compliance.load_failed')))
        });
    }

    /**
     * A bar's height, as a percentage of the chart's tallest.
     *
     * <p>Against one hundred and not against the series maximum: a scale that adjusts itself would
     * make a two-point gain look like a leap, and it is the score one reads, not its shape.
     */
    height(step: ComplianceStep): number {
        return Math.max(2, step.snapshot.score);
    }

    /** Un mouvement qui n'est pas le travail ne se peint pas comme le travail. */
    colourOf(movement: ComplianceMovement): string {
        switch (movement) {
            case 'IMPROVED':
                return 'bg-emerald-500';
            case 'DECLINED':
                return 'bg-red-500';
            case 'ESTATE_GREW':
            case 'ESTATE_SHRANK':
            case 'RULES_CHANGED':
                return 'bg-amber-400';
            default:
                return 'bg-surface-400';
        }
    }

    signed(delta: number): string {
        return delta > 0 ? `+${delta}` : String(delta);
    }
}
