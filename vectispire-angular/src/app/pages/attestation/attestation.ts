import { DatePipe } from '@angular/common';
import { Component, computed, inject, signal, ChangeDetectionStrategy } from '@angular/core';
import { RouterLink } from '@angular/router';
import { ButtonModule } from '@openng/optimus-ui/button';
import { MessageModule } from '@openng/optimus-ui/message';
import { AuditApi } from '@/app/core/api/audit.api';
import { ComplianceApi } from '@/app/core/api/compliance.api';
import { SessionStore } from '@/app/core/session.store';
import { I18nService } from '@/app/core/i18n/i18n.service';
import { TranslatePipe } from '@/app/core/i18n/translate.pipe';
import { saveDocument } from '@/app/core/download';
import { FRAMEWORKS, complianceStatusLabel, frameworkLabel } from '@/app/shared/compliance-labels';
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
    imports: [DatePipe, RouterLink, ButtonModule, MessageModule, TranslatePipe],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './attestation.html'
})
export class Attestation {
    private readonly auditApi = inject(AuditApi);
    private readonly complianceApi = inject(ComplianceApi);
    private readonly session = inject(SessionStore);
    private readonly i18n = inject(I18nService);

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
    private static readonly ORDER: readonly string[] = FRAMEWORKS;

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
        this.auditApi.verifyAuditChain().subscribe({
            next: (v) => {
                this.chain.set(v);
                this.loading.set(false);
            },
            error: () => {
                this.error.set(this.i18n.t('attestation.error_chain'));
                this.loading.set(false);
            }
        });
        this.complianceApi.complianceSummary().subscribe({
            next: (s) => this.compliance.set(s),
            // Deliberately separate: unavailable compliance must not erase a verified chain, which
            // is the demonstrable part of this page.
            error: () => this.compliance.set(null)
        });
    }

    recheck(): void {
        this.rechecking.set(true);
        this.auditApi.verifyAuditChain().subscribe({
            next: (v) => {
                this.chain.set(v);
                this.establishedAt.set(new Date());
                this.rechecking.set(false);
            },
            error: () => {
                this.error.set(this.i18n.t('attestation.error_chain'));
                this.rechecking.set(false);
            }
        });
    }

    download(): void {
        this.downloading.set(true);
        this.complianceApi.exportEvidenceBundle().subscribe({
            next: (response) => {
                saveDocument(response, 'vectispire-evidence.zip');
                this.downloading.set(false);
            },
            error: () => {
                this.error.set(this.i18n.t('attestation.error_bundle'));
                this.downloading.set(false);
            }
        });
    }

    statusTone(status: string): 'ok' | 'partial' | 'no' | 'none' {
        if (status === 'COMPLIANT') return 'ok';
        if (status === 'PARTIAL') return 'partial';
        // No data is no verdict: not red, and its zero is not shown as a score.
        if (status === 'NO_DATA') return 'none';
        return 'no';
    }

    /**
     * The framework's name and its verdict in words, through the maps every compliance screen reads.
     * The tile printed the verdict as the server spells it — "PARTIAL", "NON_COMPLIANT" under a French
     * heading — and the name by rewriting the constant's underscores.
     */
    frameworkLabel(framework: string): string {
        return frameworkLabel(this.i18n, framework);
    }

    statusLabel(status: string): string {
        return complianceStatusLabel(this.i18n, status);
    }
}
