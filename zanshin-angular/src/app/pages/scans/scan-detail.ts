import { CommonModule } from '@angular/common';
import { Component, effect, inject, input, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { MessageModule } from '@openng/optimus-ui/message';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import { ApiService } from '../../core/api.service';
import { saveDocument } from '../../core/download';
import type { ScanDetail } from '../../core/api.models';
import { LastScanTag } from '../../shared/last-scan';

/** Finding types, in words. Open table: an unknown type is shown raw. */
const TYPE_LABELS: Record<string, string> = {
    vulnerability: 'Vulnerability',
    secret: 'Secret',
    iac: 'Infrastructure',
    license: 'License',
    eol: 'End of life',
    sast: 'Source code',
    quality: 'Quality'
};

const SEVERITY_SEVERITY: Record<string, 'danger' | 'warn' | 'secondary'> = {
    critical: 'danger',
    high: 'danger',
    medium: 'warn',
    low: 'secondary',
    negligible: 'secondary',
    unknown: 'secondary'
};

import { TranslatePipe } from '../../core/i18n/translate.pipe';

@Component({
    selector: 'app-scan-detail',
    standalone: true,
    imports: [CommonModule, RouterLink, ButtonModule, CardModule, MessageModule, TableModule, TagModule, LastScanTag, TranslatePipe],
    templateUrl: './scan-detail.html'
})
export class ScanDetailPage {
    private readonly api = inject(ApiService);

    readonly id = input.required<string>();
    readonly scan = signal<ScanDetail | null>(null);
    readonly error = signal<string | null>(null);

    constructor() {
        // An `effect` rather than a call in the constructor: signal inputs are not bound yet
        // at that point, and reading `id()` there raises NG0950 — the screen sat on "Loading…"
        // and said nothing. The effect also has the right property for free: it follows
        // navigation from one scan to the next without leaving the screen.
        effect(() => {
            const id = Number(this.id());
            if (Number.isFinite(id)) this.load(id);
        });
    }

    typeLabel(type: string): string {
        return TYPE_LABELS[type] ?? type;
    }

    severityOf(severity: string): 'danger' | 'warn' | 'secondary' {
        return SEVERITY_SEVERITY[severity] ?? 'secondary';
    }

    downloadSbom(id: number): void {
        // Through HttpClient, never a navigation: the token is in memory and a navigation
        // carries none, so the browser would save the 401's empty body as a zero-byte file.
        this.api.downloadDocument(`/api/v1/scans/${id}/sbom`).subscribe({
            next: (response) => saveDocument(response, `zanshin-scan-${id}.sbom.json`)
        });
    }

    seconds(durationMs: number): number {
        return Math.round(durationMs / 100) / 10;
    }

    private load(id: number): void {
        this.api.scan(id).subscribe({
            next: (detail) => this.scan.set(detail),
            error: (response) => this.error.set(response?.status === 404 ? 'This scan does not exist.' : 'Could not load this scan.')
        });
    }
}
