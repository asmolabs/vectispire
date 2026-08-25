import { Component, OnInit, signal, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { SessionStore } from '@/app/core/session.store';
import { ApiService } from '../../core/api.service';
import { EpssFleetSummary, EpssPrioritizedIssue, ThreatIntelRecord } from '../../core/api.models';
import { ButtonModule } from '@openng/optimus-ui/button';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import { MessageModule } from '@openng/optimus-ui/message';
import { ProgressSpinnerModule } from '@openng/optimus-ui/progressspinner';
import { DialogModule } from '@openng/optimus-ui/dialog';

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
        DialogModule
    ],
    templateUrl: './epss.html'
})
export class Epss implements OnInit {
    private readonly api = inject(ApiService);
    private readonly session = inject(SessionStore);

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

    ngOnInit(): void {
        this.loadSummary();
    }

    loadSummary(): void {
        this.loading.set(true);
        this.error.set(null);

        this.api.getEpssPriorities().subscribe({
            next: (data) => {
                this.summary.set(data);
                this.loading.set(false);
            },
            error: (err) => {
                this.error.set(err?.error?.message ?? 'Erreur lors du chargement des données de priorisation EPSS.');
                this.loading.set(false);
            }
        });
    }

    syncThreatIntel(): void {
        this.syncing.set(true);
        this.syncFeedback.set(null);

        this.api.syncEpss().subscribe({
            next: (res) => {
                this.syncing.set(false);
                this.syncFeedback.set(`Synchronisation réussie : ${res.totalCves} CVEs analysées (${res.totalKev} dans CISA KEV).`);
                this.loadSummary();
            },
            error: (err) => {
                this.syncing.set(false);
                this.error.set(err?.error?.message ?? 'Échec de synchronisation du flux Threat Intelligence.');
            }
        });
    }

    searchCve(): void {
        if (!this.cveSearchQuery.trim()) return;
        this.lookupLoading.set(true);
        this.lookupResult.set(null);
        this.lookupError.set(null);
        this.lookupDialogOpen.set(true);

        this.api.lookupEpssCve(this.cveSearchQuery.trim()).subscribe({
            next: (record) => {
                this.lookupResult.set(record);
                this.lookupLoading.set(false);
            },
            error: () => {
                this.lookupLoading.set(false);
                this.lookupError.set(`Aucun enregistrement EPSS/KEV trouvé pour ${this.cveSearchQuery}.`);
            }
        });
    }

    getTierSeverity(tier: string): 'danger' | 'warn' | 'info' | 'secondary' {
        switch (tier) {
            case 'CRITICAL_ARMED': return 'danger';
            case 'HIGH_PROBABLE': return 'warn';
            case 'MEDIUM_THEORETICAL': return 'info';
            default: return 'secondary';
        }
    }

    getTierLabel(tier: string): string {
        switch (tier) {
            case 'CRITICAL_ARMED': return 'Critique / Armée (P0)';
            case 'HIGH_PROBABLE': return 'Élevée / Probable (P1)';
            case 'MEDIUM_THEORETICAL': return 'Théorique (P2)';
            default: return 'Faible Probabilité (P3)';
        }
    }

    getReachabilitySeverity(reachability: string): 'danger' | 'success' | 'info' {
        if (reachability === 'REACHABLE') return 'danger';
        if (reachability === 'UNREACHABLE') return 'success';
        return 'info';
    }
}
