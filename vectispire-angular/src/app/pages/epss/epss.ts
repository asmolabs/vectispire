import { Component, OnInit, signal, inject, ChangeDetectionStrategy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { SessionStore } from '@/app/core/session.store';
import { IntelApi } from '../../core/api/intel.api';
import { messageOf } from '../../core/api-error';
import { I18nService } from '../../core/i18n/i18n.service';
import { AiVulnerabilityAdvice, EpssFleetSummary, ThreatIntelRecord } from '../../core/api.models';
import { ButtonModule } from '@openng/optimus-ui/button';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import { MessageModule } from '@openng/optimus-ui/message';
import { ProgressSpinnerModule } from '@openng/optimus-ui/progressspinner';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { TranslatePipe } from '@/app/core/i18n/translate.pipe';

@Component({
    selector: 'app-epss',
    standalone: true,
    imports: [
        CommonModule,
        FormsModule,
        ButtonModule,
        InputTextModule,
        TableModule,
        TagModule,
        MessageModule,
        ProgressSpinnerModule,
        DialogModule,
        TranslatePipe
    ],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './epss.html'
})
export class Epss implements OnInit {
    private readonly intelApi = inject(IntelApi);
    private readonly session = inject(SessionStore);
    private readonly i18n = inject(I18nService);

    /** Synchronising the feed is an operator's act; reading the ranking is not. */
    readonly isSecurityLead = this.session.isSecurityLead;

    readonly loading = signal<boolean>(false);
    readonly syncing = signal<boolean>(false);
    readonly summary = signal<EpssFleetSummary | null>(null);
    readonly error = signal<string | null>(null);
    readonly syncFeedback = signal<string | null>(null);

    cveSearchQuery = '';
    readonly lookupResult = signal<ThreatIntelRecord | null>(null);
    readonly lookupLoading = signal<boolean>(false);
    readonly lookupError = signal<string | null>(null);
    readonly lookupDialogOpen = signal<boolean>(false);

    /**
     * The explanation of a CVE one looks at before knowing whether it concerns them.
     *
     * <p><b>This is where the question is asked, and there was nowhere to ask it.</b> The advisor
     * was reachable only from a finding in the estate; this screen is where one types a CVE read
     * elsewhere — in a bulletin, in the press — to decide whether it deserves attention. The route
     * existed, with a deterministic fallback for CVEs the estate does not carry, and no component
     * called it.
     *
     * <p>As on the list of findings, the explanation is offered only if a model is configured.
     */
    readonly aiEnabled = signal<boolean>(false);
    readonly advice = signal<AiVulnerabilityAdvice | null>(null);

    /**
     * The exploit probability as a percentage, for the deterministic wording.
     *
     * The bundles hold the sentence; the number is formatted here because neither screen imports a
     * decimal pipe, and a raw float in a sentence reads like a bug.
     */
    kevChance(probability: number | null | undefined): string {
        return ((probability ?? 0.85) * 100).toFixed(1);
    }

    readonly adviceLoading = signal<boolean>(false);
    readonly adviceError = signal<string | null>(null);

    ngOnInit(): void {
        this.loadSummary();
        this.intelApi.getAiAdvisorStatus().subscribe({
            next: (status) => this.aiEnabled.set(status?.enabled === true),
            error: () => this.aiEnabled.set(false)
        });
    }

    /** Asks for the explanation of the CVE on screen. */
    explain(): void {
        const record = this.lookupResult();
        if (!record) return;

        this.adviceLoading.set(true);
        this.adviceError.set(null);
        this.advice.set(null);

        this.intelApi.explainCveWithAi(record.cveId).subscribe({
            next: (advice) => {
                this.advice.set(advice);
                this.adviceLoading.set(false);
            },
            error: (response) => {
                this.adviceLoading.set(false);
                this.adviceError.set(messageOf(response, this.i18n.t('epss.explain_failed')));
            }
        });
    }

    loadSummary(): void {
        this.loading.set(true);
        this.error.set(null);

        this.intelApi.getEpssPriorities().subscribe({
            next: (data) => {
                this.summary.set(data);
                this.loading.set(false);
            },
            error: (err) => {
                this.error.set(err?.error?.message ?? this.i18n.t('epss.load_failed'));
                this.loading.set(false);
            }
        });
    }

    syncThreatIntel(): void {
        this.syncing.set(true);
        this.syncFeedback.set(null);

        this.intelApi.syncEpss().subscribe({
            next: (res) => {
                this.syncing.set(false);
                this.syncFeedback.set(this.i18n.t('epss.sync_succeeded', { cves: res.totalCves, kev: res.totalKev }));
                this.loadSummary();
            },
            error: (err) => {
                this.syncing.set(false);
                this.error.set(err?.error?.message ?? this.i18n.t('epss.sync_failed'));
            }
        });
    }

    searchCve(): void {
        if (!this.cveSearchQuery.trim()) return;
        this.lookupLoading.set(true);
        this.lookupResult.set(null);
        this.lookupError.set(null);
        this.lookupDialogOpen.set(true);

        // A fresh search clears the previous explanation: keeping it would show one CVE's analysis
        // under another's numbers.
        this.advice.set(null);
        this.adviceError.set(null);

        this.intelApi.lookupEpssCve(this.cveSearchQuery.trim()).subscribe({
            next: (record) => {
                this.lookupResult.set(record);
                this.lookupLoading.set(false);
            },
            error: () => {
                this.lookupLoading.set(false);
                this.lookupError.set(this.i18n.t('epss.lookup_none', { cve: this.cveSearchQuery.trim() }));
            }
        });
    }

    getTierSeverity(tier: string): 'danger' | 'warn' | 'info' | 'secondary' {
        switch (tier) {
            case 'CRITICAL_ARMED':
                return 'danger';
            case 'HIGH_PROBABLE':
                return 'warn';
            case 'MEDIUM_THEORETICAL':
                return 'info';
            default:
                return 'secondary';
        }
    }

    getTierLabel(tier: string): string {
        switch (tier) {
            case 'CRITICAL_ARMED':
                return this.i18n.t('epss.tier_critical_armed');
            case 'HIGH_PROBABLE':
                return this.i18n.t('epss.tier_high_probable');
            case 'MEDIUM_THEORETICAL':
                return this.i18n.t('epss.tier_medium_theoretical');
            default:
                return this.i18n.t('epss.tier_low');
        }
    }

    getReachabilitySeverity(reachability: string): 'danger' | 'success' | 'info' {
        if (reachability === 'REACHABLE') return 'danger';
        if (reachability === 'UNREACHABLE') return 'success';
        return 'info';
    }
}
