import { Component, inject, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { ButtonModule } from '@openng/optimus-ui/button';
import { MessageModule } from '@openng/optimus-ui/message';
import { ApiService } from '@/app/core/api.service';
import { QualityOverview, Tally } from '@/app/core/api.models';

/**
 * Code quality, aggregated.
 *
 * **If this page were only the filtered backlog it would not deserve to exist.** It therefore
 * aggregates along axes the backlog does not offer — rules, files, repositories — because in
 * front of a four-digit quality backlog, "eight rules account for seventy per cent of the debt"
 * is the only actionable framing.
 *
 * The banner says outright that these findings never fail a build. Without that sentence people
 * assume the opposite — and it is that assumption which gets a gate switched off.
 */
@Component({
    selector: 'zs-quality',
    standalone: true,
    imports: [ButtonModule, MessageModule, RouterLink],
    templateUrl: './quality.html'
})
export class Quality {
    private readonly api = inject(ApiService);
    readonly overview = signal<QualityOverview | null>(null);
    readonly error = signal<string | null>(null);

    constructor() {
        this.api.qualityOverview().subscribe({
            next: (data) => this.overview.set(data),
            error: () => this.error.set('Could not load the quality view.')
        });
    }

    groups(data: QualityOverview) {
        return [
            { title: 'Most frequent rules', rows: data.topRules },
            { title: 'Most affected files', rows: data.topFiles },
            { title: 'Densest repositories', rows: data.topTargets }
        ];
    }

    /** A share relative to the largest in the group: that is the comparison that matters,
     *  not the proportion of the total. */
    share(row: Tally, rows: Tally[]): number {
        const largest = Math.max(...rows.map((item) => item.count), 1);
        return Math.round((row.count / largest) * 100);
    }
}
