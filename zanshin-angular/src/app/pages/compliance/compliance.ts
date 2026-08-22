import { CommonModule } from '@angular/common';
import { Component, computed, inject, signal } from '@angular/core';
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
    imports: [CommonModule, CardModule, ButtonModule, MessageModule, TableModule, TagModule, TranslatePipe],
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
    readonly error = signal<string | null>(null);

    readonly frameworks = [
        { key: 'NIS_2', label: 'NIS 2 Directive', desc: 'EU 2022/2555 — Supply Chain & Vulnerability Mgmt' },
        { key: 'DORA', label: 'DORA', desc: 'EU 2022/2554 — Digital Operational Resilience' },
        { key: 'ISO_27001', label: 'ISO/IEC 27001:2022', desc: 'Annex A Information Security Controls' },
        { key: 'PCI_DSS', label: 'PCI-DSS v4.0', desc: 'Payment Card Security Standard' }
    ];

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

    statusSeverity(status: string): 'success' | 'warn' | 'danger' {
        if (status === 'COMPLIANT') return 'success';
        if (status === 'PARTIAL') return 'warn';
        return 'danger';
    }
}
