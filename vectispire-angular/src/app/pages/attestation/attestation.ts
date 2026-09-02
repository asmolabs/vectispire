import { CommonModule } from '@angular/common';
import { Component, computed, inject, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { ButtonModule } from '@openng/optimus-ui/button';
import { MessageModule } from '@openng/optimus-ui/message';
import { ApiService } from '@/app/core/api.service';
import { SessionStore } from '@/app/core/session.store';
import { TranslatePipe } from '@/app/core/i18n/translate.pipe';
import { saveDocument } from '@/app/core/download';
import type { AuditVerification, ComplianceEvaluation, ComplianceSummary } from '@/app/core/api.models';

/**
 * What the estate looked like, at an hour, with the proof attached.
 *
 * <p><b>Why a page rather than a fifth link.</b> The four screens an auditor needs already exist —
 * the audit log and its chain check, the compliance summary, the gate policy, the evidence
 * bundle — and not one of them carries a time. An auditor is not asking "where are you"; they are
 * asking "where were you on the day I looked", and a screen with no hour cannot answer that.
 *
 * <p>The chain check leads, because it is the only claim here that can be demonstrated on the
 * spot: the rest is measurement, that one is proof.
 */
@Component({
    selector: 'app-attestation',
    standalone: true,
    imports: [CommonModule, RouterLink, ButtonModule, MessageModule, TranslatePipe],
    templateUrl: './attestation.html'
})
export class Attestation {
    private readonly api = inject(ApiService);
    private readonly session = inject(SessionStore);

    readonly chain = signal<AuditVerification | null>(null);
    readonly compliance = signal<ComplianceSummary | null>(null);
    readonly loading = signal(true);
    readonly error = signal<string | null>(null);
    readonly downloading = signal(false);
    readonly rechecking = signal(false);

    /** Frozen when the page loads, not read from the clock on each change detection. */
    readonly establishedAt = signal(new Date());
    readonly establishedBy = computed(() => this.session.user()?.username ?? '');

    /**
     * The six, in the order the compliance screen already uses.
     *
     * <p>Ordered here rather than trusted from the server: a grid whose columns move between two
     * loads is a grid nobody can compare against last month's screenshot, which is most of what
     * this page is for.
     */
    private static readonly ORDER = ['NIS_2', 'ISO_27001', 'EU_CRA', 'DORA', 'PCI_DSS', 'SOC_2'];

    readonly frameworks = computed<ComplianceEvaluation[]>(() => {
        const evaluations = this.compliance()?.evaluations ?? [];
        return [...evaluations].sort(
            (a, b) => Attestation.ORDER.indexOf(a.framework) - Attestation.ORDER.indexOf(b.framework)
        );
    });

    constructor() {
        this.reload();
    }

    reload(): void {
        this.loading.set(true);
        this.api.verifyAuditChain().subscribe({
            next: (v) => { this.chain.set(v); this.loading.set(false); },
            error: () => { this.error.set('La vérification de la chaîne d\'audit a échoué.'); this.loading.set(false); }
        });
        this.api.complianceSummary().subscribe({
            next: (s) => this.compliance.set(s),
            // Volontairement séparé : une conformité indisponible ne doit pas effacer une chaîne
            // vérifiée, qui est la partie démontrable de cette page.
            error: () => this.compliance.set(null)
        });
    }

    recheck(): void {
        this.rechecking.set(true);
        this.api.verifyAuditChain().subscribe({
            next: (v) => { this.chain.set(v); this.establishedAt.set(new Date()); this.rechecking.set(false); },
            error: () => { this.error.set('La vérification de la chaîne d\'audit a échoué.'); this.rechecking.set(false); }
        });
    }

    download(): void {
        this.downloading.set(true);
        this.api.exportEvidenceBundle().subscribe({
            next: (response) => { saveDocument(response, 'vectispire-evidence.zip'); this.downloading.set(false); },
            error: () => { this.error.set('Le paquet de preuves n\'a pas pu être produit.'); this.downloading.set(false); }
        });
    }

    statusTone(status: string): 'ok' | 'partial' | 'no' {
        if (status === 'COMPLIANT') return 'ok';
        if (status === 'PARTIAL') return 'partial';
        return 'no';
    }

    frameworkLabel(framework: string): string {
        return framework.replace('_', ' ').replace('NIS 2', 'NIS 2').replace('EU CRA', 'EU CRA');
    }
}
