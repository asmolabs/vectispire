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
    template: `
        <div class="card">
            <div class="font-semibold text-xl mb-1">Quality</div>
            <p class="text-muted-color mb-4">What source analysis reports about how the code is written, rather than about how safe it is.</p>

            <p-message severity="info" styleClass="w-full mb-4"
                text="These findings never fail a build. They are visible, exportable, and have no say in the continuous-integration gate." />

            @if (overview(); as data) {
                <div class="flex flex-wrap gap-6 mb-6">
                    <div><span class="text-2xl font-medium">{{ data.openCount }}</span><span class="text-muted-color ml-2">open findings</span></div>
                    <div><span class="text-2xl font-medium">{{ data.ruleCount }}</span><span class="text-muted-color ml-2">distinct rules</span></div>
                    <div><span class="text-2xl font-medium">{{ data.fileCount }}</span><span class="text-muted-color ml-2">files affected</span></div>
                </div>

                <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
                    @for (group of groups(data); track group.title) {
                        <div>
                            <div class="font-medium mb-3">{{ group.title }}</div>
                            @for (row of group.rows; track row.label) {
                                <div class="mb-3">
                                    <div class="flex justify-between text-sm mb-1">
                                        <span class="truncate pr-2">{{ row.label ?? '—' }}</span>
                                        <span class="text-muted-color">{{ row.count }}</span>
                                    </div>
                                    <div class="bg-surface-200 dark:bg-surface-700 rounded" style="height: 6px">
                                        <div class="bg-primary rounded" style="height: 6px" [style.width.%]="share(row, group.rows)"></div>
                                    </div>
                                </div>
                            } @empty {
                                <div class="text-muted-color text-sm">No finding.</div>
                            }
                        </div>
                    }
                </div>

                <div class="mt-6">
                    <p-button label="See every quality finding" [text]="true" [routerLink]="['/issues']" [queryParams]="{ type: 'quality' }" />
                </div>
            } @else if (error()) {
                <p-message severity="error" [text]="error()!" styleClass="w-full" />
            }
        </div>
    `
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
