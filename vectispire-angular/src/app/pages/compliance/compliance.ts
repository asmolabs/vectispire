import { CommonModule } from '@angular/common';
import { CosignCliHelper } from '@/app/core/api.models';
import { Component, computed, inject, signal, ChangeDetectionStrategy } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { ButtonModule } from '@openng/optimus-ui/button';
import { MessageModule } from '@openng/optimus-ui/message';
import { SelectModule } from '@openng/optimus-ui/select';
import { SessionStore } from '@/app/core/session.store';
import { ComplianceApi } from '../../core/api/compliance.api';
import { DocumentsApi } from '../../core/api/documents.api';
import { saveDocument } from '../../core/download';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { I18nService } from '../../core/i18n/i18n.service';
import type { ComplianceSummary } from '../../core/api.models';
import { ComplianceSummaryView } from '../../shared/compliance-summary';
import { LatestRequest } from '@/app/core/latest-request';
import { messageOf } from '@/app/core/api-error';

@Component({
    selector: 'app-compliance',
    standalone: true,
    imports: [
        CommonModule,
        FormsModule,
        DialogModule,
        ButtonModule,
        MessageModule,
        SelectModule,
        TranslatePipe,
        ComplianceSummaryView
    ],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './compliance.html'
})
export class Compliance {
    private readonly summaryRequest = new LatestRequest();

    private readonly complianceApi = inject(ComplianceApi);
    private readonly documentsApi = inject(DocumentsApi);
    private readonly session = inject(SessionStore);

    /**
     * Whether this account may use the governance controls on this page.
     *
     * **The interface used to offer them to everybody**, and the server used to accept them from
     * everybody — consistent, and wrong in both halves. The server now refuses; a button that
     * answers 403 tells a reader the product is broken rather than that the action is not theirs,
     * so the button goes with the permission.
     */
    readonly isSecurityLead = this.session.isSecurityLead;
    /** The evidence bundle is a read: importing VEX beside it is not. */
    readonly canReadGovernance = this.session.canReadGovernance;
    readonly i18n = inject(I18nService);

    readonly summary = signal<ComplianceSummary | null>(null);

    readonly selectedTarget = signal<string>('ALL');
    /**
     * The target a request is scoped to — none for the estate. `'ALL'` is the selector's value, not an
     * identifier: sent as `?targetId=ALL`, the server happened to read it as the estate, but audited
     * the export as made "for ALL" and the file was saved as `vectispire-compliance-ALL.pdf`.
     */
    private readonly scopedTargetId = computed(() => {
        const sel = this.selectedTarget();
        return sel === 'ALL' ? undefined : sel;
    });
    readonly targetsList = signal<{ targetId: string; name: string; type: string }[]>([]);
    readonly loading = signal<boolean>(true);
    readonly exporting = signal<boolean>(false);
    readonly exportingBundle = signal<boolean>(false);
    readonly exportingVex = signal<boolean>(false);
    readonly exportingCsaf = signal<boolean>(false);
    readonly exportingCycloneDx = signal<boolean>(false);
    readonly error = signal<string | null>(null);

    readonly targetOptions = computed(() => {
        this.i18n.translations();
        const list = this.targetsList();
        return [
            { label: this.i18n.t('compliance.global_view'), value: 'ALL' },
            ...list.map((t) => ({
                label: `${t.type === 'REPOSITORY' ? '📁' : '📦'} ${t.name}`,
                value: t.targetId
            }))
        ];
    });

    // Crypto & Cosign Verifier
    readonly downloadingPubKey = signal<boolean>(false);
    readonly verifyOpen = signal<boolean>(false);
    readonly verifying = signal<boolean>(false);
    /**
     * Signals, not fields: a file picker fills them from `FileReader.onload`, and in a zoneless
     * application nothing renders after a callback that only assigns a plain field. The textarea
     * stayed empty and Verify stayed disabled after a file had been read.
     */
    readonly verifyPayload = signal('');
    readonly verifySignature = signal('');
    verifyPublicKey = '';
    readonly verifyResult = signal<{
        valid: boolean;
        keyId: string;
        vectispireKey: boolean;
        algorithm: string;
        message: string;
    } | null>(null);
    /** Valid under Vectispire's own key: the only result shown as authentic. */
    readonly verifyAuthentic = computed(() => !!this.verifyResult()?.valid && !!this.verifyResult()?.vectispireKey);
    /** Valid under a key the caller supplied: proves the match, not Vectispire's signature. */
    readonly verifyForeign = computed(() => !!this.verifyResult()?.valid && !this.verifyResult()?.vectispireKey);
    readonly verifyError = signal<string | null>(null);
    readonly cosignCliInfo = signal<CosignCliHelper | null>(null);

    // VEX Ingest
    readonly importOpen = signal<boolean>(false);
    readonly importing = signal<boolean>(false);
    /** A signal for the same reason as `verifyPayload`: the file picker writes it from a callback. */
    readonly importJson = signal('');
    readonly importSuccess = signal<string | null>(null);
    readonly importError = signal<string | null>(null);

    constructor() {
        this.loadSummary();
    }

    loadSummary(): void {
        this.loading.set(true);
        this.error.set(null);
        this.summaryRequest.run(this.complianceApi.complianceSummary(this.scopedTargetId()), {
            next: (data) => {
                this.summary.set(data);
                if (data.targets && data.targets.length > 0) {
                    this.targetsList.set(
                        data.targets.map((t) => ({ targetId: t.targetId, name: t.name, type: t.type }))
                    );
                }
                this.loading.set(false);
            },
            error: () => {
                this.error.set(this.i18n.t('compliance.error_load'));
                this.loading.set(false);
            }
        });
    }

    onTargetChange(targetId: string | null): void {
        const tid =
            !targetId || targetId === 'ALL' || targetId === 'null' || targetId === 'undefined' ? 'ALL' : targetId;
        this.selectedTarget.set(tid);
        this.loadSummary();
    }

    exportPdf(): void {
        this.exporting.set(true);
        const tid = this.scopedTargetId();
        this.complianceApi.exportCompliancePdf(tid).subscribe({
            next: (response) => {
                saveDocument(
                    response,
                    tid ? `vectispire-compliance-${tid.replace(':', '-')}.pdf` : 'vectispire-compliance-report.pdf'
                );
                this.exporting.set(false);
            },
            error: () => {
                this.error.set(this.i18n.t('compliance.error_export_pdf'));
                this.exporting.set(false);
            }
        });
    }

    exportEvidenceBundle(): void {
        this.exportingBundle.set(true);
        this.complianceApi.exportEvidenceBundle().subscribe({
            next: (response) => {
                saveDocument(response, 'vectispire-audit-evidence-bundle.zip');
                this.exportingBundle.set(false);
            },
            error: () => {
                this.error.set(this.i18n.t('compliance.error_export_bundle'));
                this.exportingBundle.set(false);
            }
        });
    }

    exportOpenVex(): void {
        this.exportingVex.set(true);
        this.documentsApi.getAggregateVex().subscribe({
            next: (vexDoc) => {
                const blob = new Blob([JSON.stringify(vexDoc, null, 2)], { type: 'application/json' });
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'vectispire-aggregate-openvex.json';
                a.click();
                window.URL.revokeObjectURL(url);
                this.exportingVex.set(false);
            },
            error: () => {
                this.error.set(this.i18n.t('compliance.error_export_vex'));
                this.exportingVex.set(false);
            }
        });
    }

    exportCsaf(): void {
        this.exportingCsaf.set(true);
        this.documentsApi.getAggregateCsaf().subscribe({
            next: (csafDoc) => {
                const blob = new Blob([JSON.stringify(csafDoc, null, 2)], { type: 'application/json' });
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'vectispire-aggregate-csaf.json';
                a.click();
                window.URL.revokeObjectURL(url);
                this.exportingCsaf.set(false);
            },
            error: () => {
                this.error.set(this.i18n.t('compliance.error_export_csaf'));
                this.exportingCsaf.set(false);
            }
        });
    }

    exportCycloneDx(): void {
        this.exportingCycloneDx.set(true);
        this.documentsApi.getAggregateCycloneDx().subscribe({
            next: (cdxDoc) => {
                const blob = new Blob([JSON.stringify(cdxDoc, null, 2)], { type: 'application/json' });
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'vectispire-aggregate-cyclonedx-vex.json';
                a.click();
                window.URL.revokeObjectURL(url);
                this.exportingCycloneDx.set(false);
            },
            error: () => {
                this.error.set(this.i18n.t('compliance.error_export_cyclonedx'));
                this.exportingCycloneDx.set(false);
            }
        });
    }

    openImport(): void {
        this.importJson.set('');
        this.importSuccess.set(null);
        this.importError.set(null);
        this.importOpen.set(true);
    }

    onFileSelected(event: Event): void {
        const input = event.target as HTMLInputElement;
        if (!input.files || input.files.length === 0) return;
        const file = input.files[0];
        const reader = new FileReader();
        reader.onload = (e) => {
            this.importJson.set(e.target?.result as string);
        };
        reader.readAsText(file);
    }

    submitIngestVex(): void {
        if (!this.importJson().trim()) return;
        this.importing.set(true);
        this.importSuccess.set(null);
        this.importError.set(null);

        try {
            const parsed: unknown = JSON.parse(this.importJson());
            this.documentsApi.ingestVex(parsed).subscribe({
                next: (res) => {
                    this.importing.set(false);
                    const count = res?.triagedIssues ?? 0;
                    const applied = (res?.appliedCves ?? []).join(', ');
                    this.importSuccess.set(
                        this.i18n.t('compliance.vex_ingested', {
                            count,
                            applied: applied || this.i18n.t('compliance.vex_no_match')
                        })
                    );
                    this.loadSummary();
                },
                error: (err) => {
                    this.importing.set(false);
                    this.importError.set(messageOf(err, this.i18n.t('compliance.error_vex_ingest')));
                }
            });
        } catch (e) {
            this.importing.set(false);
            this.importError.set(
                this.i18n.t('compliance.error_invalid_json', { detail: e instanceof Error ? e.message : String(e) })
            );
        }
    }

    downloadPublicKey(): void {
        this.downloadingPubKey.set(true);
        this.documentsApi.getPublicKeyPem().subscribe({
            next: (pem) => {
                const blob = new Blob([pem], { type: 'application/x-pem-file' });
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'vectispire-signing-key.pub';
                a.click();
                window.URL.revokeObjectURL(url);
                this.downloadingPubKey.set(false);
            },
            error: () => {
                this.error.set(this.i18n.t('compliance.error_public_key'));
                this.downloadingPubKey.set(false);
            }
        });
    }

    openVerifier(): void {
        this.verifyPayload.set('');
        this.verifySignature.set('');
        this.verifyPublicKey = '';
        this.verifyResult.set(null);
        this.verifyError.set(null);
        this.verifyOpen.set(true);

        this.documentsApi.getCosignCliHelper().subscribe({
            next: (info) => this.cosignCliInfo.set(info),
            error: () => {}
        });
    }

    onVerifyPayloadSelected(event: Event): void {
        const input = event.target as HTMLInputElement;
        if (!input.files || input.files.length === 0) return;
        const file = input.files[0];
        const reader = new FileReader();
        reader.onload = (e) => {
            this.verifyPayload.set(e.target?.result as string);
        };
        reader.readAsText(file);
    }

    onVerifySigSelected(event: Event): void {
        const input = event.target as HTMLInputElement;
        if (!input.files || input.files.length === 0) return;
        const file = input.files[0];
        const reader = new FileReader();
        reader.onload = (e) => {
            this.verifySignature.set((e.target?.result as string).trim());
        };
        reader.readAsText(file);
    }

    submitVerification(): void {
        if (!this.verifyPayload().trim() || !this.verifySignature().trim()) return;
        this.verifying.set(true);
        this.verifyResult.set(null);
        this.verifyError.set(null);

        this.documentsApi
            .verifyCryptoSignature(
                this.verifyPayload(),
                this.verifySignature(),
                this.verifyPublicKey.trim() || undefined
            )
            .subscribe({
                next: (res) => {
                    this.verifying.set(false);
                    this.verifyResult.set(res);
                },
                error: (err) => {
                    this.verifying.set(false);
                    this.verifyError.set(messageOf(err, this.i18n.t('compliance.error_verify')));
                }
            });
    }
}
