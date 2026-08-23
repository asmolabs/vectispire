import { CommonModule } from '@angular/common';
import { Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { MessageModule } from '@openng/optimus-ui/message';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import { ApiService } from '../../core/api.service';
import { saveDocument } from '../../core/download';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { I18nService } from '../../core/i18n/i18n.service';
import type { ComplianceSummary, ComplianceEvaluation } from '../../core/api.models';

@Component({
    selector: 'app-compliance',
    standalone: true,
    imports: [CommonModule, FormsModule, DialogModule, CardModule, ButtonModule, MessageModule, TableModule, TagModule, TranslatePipe],
    templateUrl: './compliance.html'
})
export class Compliance {
    private readonly api = inject(ApiService);
    readonly i18n = inject(I18nService);
    readonly Math = Math;

    readonly summary = signal<ComplianceSummary | null>(null);
    readonly selectedFramework = signal<string>('NIS_2');
    readonly loading = signal<boolean>(true);
    readonly exporting = signal<boolean>(false);
    readonly exportingBundle = signal<boolean>(false);
    readonly exportingVex = signal<boolean>(false);
    readonly exportingCsaf = signal<boolean>(false);
    readonly error = signal<string | null>(null);

    // VEX Ingest
    readonly importOpen = signal<boolean>(false);
    readonly importing = signal<boolean>(false);
    importJson = '';
    readonly importSuccess = signal<string | null>(null);
    readonly importError = signal<string | null>(null);

    readonly frameworks = [
        { key: 'NIS_2', label: 'NIS 2 Directive', desc: 'EU 2022/2555 — Supply Chain & Vulnerability Mgmt' },
        { key: 'DORA', label: 'DORA', desc: 'EU 2022/2554 — Digital Operational Resilience' },
        { key: 'ISO_27001', label: 'ISO/IEC 27001:2022', desc: 'Annex A Information Security Controls' },
        { key: 'PCI_DSS', label: 'PCI-DSS v4.0', desc: 'Payment Card Security Standard' },
        { key: 'EU_CRA', label: 'Cyber Resilience Act (EU CRA)', desc: 'EU Digital Products Security & 24h CSIRT Notification' }
    ];

    frameworkLabel(key: string): string {
        return this.frameworks.find((f) => f.key === key)?.label ?? key.replace('_', ' ');
    }

    frameworkDesc(key: string): string {
        return this.frameworks.find((f) => f.key === key)?.desc ?? key;
    }

    readonly activeEvaluation = computed<ComplianceEvaluation | null>(() => {
        const s = this.summary();
        if (!s) return null;
        return s.evaluations.find((e) => e.framework === this.selectedFramework()) ?? null;
    });

    constructor() {
        this.loadSummary();
    }

    loadSummary(): void {
        this.loading.set(true);
        this.error.set(null);
        this.api.complianceSummary().subscribe({
            next: (data) => {
                this.summary.set(data);
                this.loading.set(false);
            },
            error: () => {
                this.error.set('Failed to load compliance summary.');
                this.loading.set(false);
            }
        });
    }

    selectFramework(key: string): void {
        this.selectedFramework.set(key);
    }

    exportPdf(): void {
        this.exporting.set(true);
        this.api.exportCompliancePdf().subscribe({
            next: (response) => {
                saveDocument(response, 'zanshin-compliance-report.pdf');
                this.exporting.set(false);
            },
            error: () => {
                this.error.set('Failed to export compliance PDF report.');
                this.exporting.set(false);
            }
        });
    }

    exportEvidenceBundle(): void {
        this.exportingBundle.set(true);
        this.api.exportEvidenceBundle().subscribe({
            next: (response) => {
                saveDocument(response, 'zanshin-audit-evidence-bundle.zip');
                this.exportingBundle.set(false);
            },
            error: () => {
                this.error.set('Failed to export audit evidence bundle.');
                this.exportingBundle.set(false);
            }
        });
    }

    exportOpenVex(): void {
        this.exportingVex.set(true);
        this.api.getAggregateVex().subscribe({
            next: (vexDoc) => {
                const blob = new Blob([JSON.stringify(vexDoc, null, 2)], { type: 'application/json' });
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'zanshin-aggregate-openvex.json';
                a.click();
                window.URL.revokeObjectURL(url);
                this.exportingVex.set(false);
            },
            error: () => {
                this.error.set('Failed to export OpenVEX advisory.');
                this.exportingVex.set(false);
            }
        });
    }

    exportCsaf(): void {
        this.exportingCsaf.set(true);
        this.api.getAggregateCsaf().subscribe({
            next: (csafDoc) => {
                const blob = new Blob([JSON.stringify(csafDoc, null, 2)], { type: 'application/json' });
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'zanshin-aggregate-csaf.json';
                a.click();
                window.URL.revokeObjectURL(url);
                this.exportingCsaf.set(false);
            },
            error: () => {
                this.error.set('Failed to export OASIS CSAF 2.0 advisory.');
                this.exportingCsaf.set(false);
            }
        });
    }

    openImport(): void {
        this.importJson = '';
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
            this.importJson = e.target?.result as string;
        };
        reader.readAsText(file);
    }

    submitIngestVex(): void {
        if (!this.importJson.trim()) return;
        this.importing.set(true);
        this.importSuccess.set(null);
        this.importError.set(null);

        try {
            const parsed = JSON.parse(this.importJson);
            this.api.ingestVex(parsed).subscribe({
                next: (res: any) => {
                    this.importing.set(false);
                    const count = res?.triagedIssues ?? 0;
                    const applied = (res?.appliedCves ?? []).join(', ');
                    this.importSuccess.set(`Document VEX ingéré avec succès : ${count} vulnérabilité(s) classée(s) automatiquement (${applied || 'aucune correspondance'}).`);
                    this.loadSummary();
                },
                error: (err) => {
                    this.importing.set(false);
                    this.importError.set(err?.error?.message ?? 'Erreur lors de l\'ingestion du document VEX.');
                }
            });
        } catch (e: any) {
            this.importing.set(false);
            this.importError.set('Format JSON invalide : ' + e.message);
        }
    }

    statusSeverity(status: string): 'success' | 'warn' | 'danger' {
        if (status === 'COMPLIANT') return 'success';
        if (status === 'PARTIAL') return 'warn';
        return 'danger';
    }
}
