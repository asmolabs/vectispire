import { Component, OnInit, signal, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { SessionStore } from '@/app/core/session.store';
import { ApiService } from '../../core/api.service';
import { messageOf } from '../../core/api-error';
import { I18nService } from '../../core/i18n/i18n.service';
import { AiVulnerabilityAdvice, EpssFleetSummary, EpssPrioritizedIssue, ThreatIntelRecord } from '../../core/api.models';
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
        DialogModule, TranslatePipe],
    templateUrl: './epss.html'
})
export class Epss implements OnInit {
    private readonly api = inject(ApiService);
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
     * L'explication d'une CVE qu'on regarde avant de savoir si elle vous concerne.
     *
     * <p><b>C'est ici que la question se pose, et il n'y avait aucun endroit pour la poser.</b>
     * Le conseiller n'était atteignable que depuis un constat du parc ; cet écran est celui où
     * l'on tape une CVE lue ailleurs — dans un bulletin, dans la presse — pour décider si elle
     * mérite qu'on s'y arrête. La route existait, avec un repli déterministe pour les CVE que le
     * parc ne porte pas, et aucun composant ne l'appelait.
     *
     * <p>Comme sur la liste des constats, l'explication n'est offerte que si un modèle est
     * configuré.
     */
    readonly aiEnabled = signal<boolean>(false);
    readonly advice = signal<AiVulnerabilityAdvice | null>(null);
    readonly adviceLoading = signal<boolean>(false);
    readonly adviceError = signal<string | null>(null);

    ngOnInit(): void {
        this.loadSummary();
        this.api.getAiAdvisorStatus().subscribe({
            next: (status) => this.aiEnabled.set(status?.enabled === true),
            error: () => this.aiEnabled.set(false)
        });
    }

    /** Demande l'explication de la CVE affichée. */
    explain(): void {
        const record = this.lookupResult();
        if (!record) return;

        this.adviceLoading.set(true);
        this.adviceError.set(null);
        this.advice.set(null);

        this.api.explainCveWithAi(record.cveId).subscribe({
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

        // Une recherche neuve efface l'explication de la précédente : la garder afficherait
        // l'analyse d'une CVE sous les chiffres d'une autre.
        this.advice.set(null);
        this.adviceError.set(null);

        this.api.lookupEpssCve(this.cveSearchQuery.trim()).subscribe({
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
