import { CommonModule } from '@angular/common';
import { Component, computed, inject, signal, ChangeDetectionStrategy } from '@angular/core';
import { MessageModule } from '@openng/optimus-ui/message';
import { messageOf } from '@/app/core/api-error';
import { RemediationApi } from '@/app/core/api/remediation.api';
import { I18nService } from '@/app/core/i18n/i18n.service';
import { TranslatePipe } from '@/app/core/i18n/translate.pipe';
import type { RemediationBySeverity, RemediationDistribution } from '@/app/core/api.models';

/**
 * Remediation times, by the distribution's tail and not by the mean.
 *
 * **A mean is dragged by the volume of easy fixes.** What describes a process is the share that
 * met its deadline, the 90th percentile, and the age of the oldest item still open — the three
 * this screen puts on the same footing.
 *
 * **The oldest open item is at the top, not in a column.** It is the line no mean can show and
 * the first an assessor asks for; filing it in the table would make it one datum among nine.
 *
 * A severity with no deadline set shows no percentage. A rate computed against an absent rule is
 * not one, and it would be quoted.
 */
@Component({
    selector: 'zs-remediation-delays',
    standalone: true,
    imports: [CommonModule, MessageModule, TranslatePipe],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './remediation-delays.html'
})
export class RemediationDelays {
    private readonly remediationApi = inject(RemediationApi);
    private readonly i18n = inject(I18nService);

    readonly distribution = signal<RemediationDistribution | null>(null);
    readonly error = signal<string | null>(null);

    readonly rows = computed<RemediationBySeverity[]>(() => this.distribution()?.bySeverity ?? []);

    constructor() {
        this.remediationApi.remediationDistribution(90).subscribe({
            next: (data) => this.distribution.set(data),
            error: (failure) => this.error.set(messageOf(failure, this.i18n.t('delays.load_failed')))
        });
    }

    /**
     * Whether the oldest open item is past its own severity's deadline.
     *
     * <p><b>Twenty-one days in red against a ninety-day deadline was a false alarm.</b> The banner
     * painted the age, never the overrun — and it is the overrun that is worth flagging; the age of
     * an item that is on time is information, not a problem.
     */
    readonly oldestIsOverdue = computed(() => {
        const data = this.distribution();
        if (!data || data.oldestOpenDays === null) {
            return false;
        }
        const row = this.rows().find((entry) => entry.severity === data.oldestOpenSeverity);
        return !!row && row.windowDays > 0 && data.oldestOpenDays > row.windowDays;
    });

    /** Vert au-dessus de quatre-vingt-dix, ambre au-dessus de soixante-quinze, rouge sinon. */
    barColour(row: RemediationBySeverity): string {
        const share = row.percentageWithinSla ?? 0;
        return share >= 90 ? '#059669' : share >= 75 ? '#d97706' : '#b91c1c';
    }

    /**
     * A severity nobody has given a deadline has nothing to meet.
     *
     * <p><b>Distinct from "nothing to measure", and the two were conflated.</b> The condition also
     * tested the percentage, so a severity that had a deadline but nothing resolved within the
     * window showed "15 d" as its deadline and "no deadline set" right beside it — two
     * contradictory sentences on the same row.
     */
    hasDeadline(row: RemediationBySeverity): boolean {
        return row.windowDays > 0;
    }

    /**
     * The deadline exists, but nothing was resolved within the window to measure it against.
     *
     * <p>This is neither a rate of zero nor an absent deadline: it is the absence of material.
     * Showing `0 %` would read as "we never meet the deadlines" where the true sentence is "nothing
     * was closed in these ninety days".
     */
    nothingToMeasure(row: RemediationBySeverity): boolean {
        return row.windowDays > 0 && row.percentageWithinSla === null;
    }
}
