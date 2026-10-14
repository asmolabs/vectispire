import { Component, OnInit, signal, inject, ChangeDetectionStrategy } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ExposureApi } from '../../core/api/exposure.api';
import { BlastRadiusReport, TopImpactPackage } from '../../core/api.models';
import { ButtonModule } from '@openng/optimus-ui/button';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import { MessageModule } from '@openng/optimus-ui/message';
import { ProgressSpinnerModule } from '@openng/optimus-ui/progressspinner';
import { I18nService } from '@/app/core/i18n/i18n.service';
import { TranslatePipe } from '@/app/core/i18n/translate.pipe';
import { messageOf } from '@/app/core/api-error';
import { LatestRequest } from '@/app/core/latest-request';
import { TargetKindPipe } from '@/app/shared/target-kind';
import { SearchBound, SearchBoundHint } from '@/app/shared/search-bound';

@Component({
    selector: 'app-blast-radius',
    imports: [
        SearchBound,
        SearchBoundHint,
        FormsModule,
        ButtonModule,
        InputTextModule,
        TableModule,
        TagModule,
        MessageModule,
        ProgressSpinnerModule,
        TranslatePipe,
        TargetKindPipe
    ],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './blast-radius.html'
})
export class BlastRadius implements OnInit {
    private readonly exposureApi = inject(ExposureApi);
    private readonly i18n = inject(I18nService);

    searchQuery = '';
    /**
     * Two flags, one per request. A single `loading` was shared by the ranking and the exploration:
     * whichever answered first switched it off, and the page showed the ranking or an empty detail
     * while the other was still on its way.
     */
    readonly topLoading = signal<boolean>(false);
    readonly exploring = signal<boolean>(false);
    readonly error = signal<string | null>(null);
    /** The ranking's own failure: swallowed, it left an overview with no component and no reason. */
    readonly topError = signal<string | null>(null);
    readonly report = signal<BlastRadiusReport | null>(null);
    readonly topPackages = signal<TopImpactPackage[]>([]);
    readonly selectedNodeId = signal<string | null>(null);

    /** Latest click wins: clicking two components quickly showed whichever graph answered last. */
    private readonly exploration = new LatestRequest();

    ngOnInit(): void {
        this.loadTopPackages();
    }

    loadTopPackages(): void {
        this.topLoading.set(true);
        this.topError.set(null);
        this.exposureApi.getTopBlastRadius(12).subscribe({
            next: (data) => {
                this.topPackages.set(data);
                this.topLoading.set(false);
            },
            error: (err) => {
                this.topError.set(messageOf(err, this.i18n.t('blast_radius.error_top')));
                this.topLoading.set(false);
            }
        });
    }

    explore(query?: string): void {
        if (query !== undefined) {
            this.searchQuery = query;
        }

        const trimmed = this.searchQuery.trim();
        if (!trimmed) {
            this.resetSearch();
            return;
        }

        this.exploring.set(true);
        this.error.set(null);

        this.exploration.run(this.exposureApi.exploreBlastRadius(trimmed), {
            next: (data) => {
                this.report.set(data);
                this.exploring.set(false);
            },
            error: (err) => {
                this.error.set(messageOf(err, this.i18n.t('blast_radius.error_explore')));
                this.exploring.set(false);
            }
        });
    }

    resetSearch(): void {
        // An exploration still on its way would bring a graph back after the reader asked for none.
        this.exploration.cancel();
        this.exploring.set(false);
        this.searchQuery = '';
        this.report.set(null);
        this.selectedNodeId.set(null);
    }

    selectQuickPackage(pkg: string): void {
        this.searchQuery = pkg;
        this.explore(pkg);
    }

    selectNode(node: { id: string; label: string; type: string }): void {
        this.selectedNodeId.set(node.id);
        this.selectQuickPackage(node.label);
    }

    getScoreSeverity(score: number): 'success' | 'warn' | 'danger' {
        if (score >= 70) return 'danger';
        if (score >= 40) return 'warn';
        return 'success';
    }
}
