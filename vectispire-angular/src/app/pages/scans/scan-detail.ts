import { CommonModule } from '@angular/common';
import { Component, effect, inject, input, signal, ChangeDetectionStrategy } from '@angular/core';
import { RouterLink } from '@angular/router';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { MessageModule } from '@openng/optimus-ui/message';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import { DocumentsApi } from '../../core/api/documents.api';
import { ScansApi } from '../../core/api/scans.api';
import { I18nService } from '../../core/i18n/i18n.service';
import { saveDocument } from '../../core/download';
import type { ScanDetail } from '../../core/api.models';
import { LastScanTag } from '../../shared/last-scan';
import { RuleCoverageBanner } from '../../shared/rule-coverage-banner';

/**
 * Finding types, in words — the keys of `issues.types`, read at render time because the language
 * changes at runtime. Open table: an unknown type is shown raw.
 */
const KNOWN_TYPES = new Set(['vulnerability', 'secret', 'iac', 'license', 'eol', 'sast', 'quality']);

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
    imports: [
        CommonModule,
        RouterLink,
        ButtonModule,
        CardModule,
        MessageModule,
        TableModule,
        TagModule,
        LastScanTag,
        TranslatePipe,
        RuleCoverageBanner
    ],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './scan-detail.html'
})
export class ScanDetailPage {
    private readonly documentsApi = inject(DocumentsApi);
    private readonly scansApi = inject(ScansApi);
    private readonly i18n = inject(I18nService);

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
        return KNOWN_TYPES.has(type) ? this.i18n.t(`issues.types.${type}`) : type;
    }

    severityOf(severity: string): 'danger' | 'warn' | 'secondary' {
        return SEVERITY_SEVERITY[severity] ?? 'secondary';
    }

    downloadSbom(id: number): void {
        // Through HttpClient, never a navigation: the token is in memory and a navigation
        // carries none, so the browser would save the 401's empty body as a zero-byte file.
        this.download(`/api/v1/scans/${id}/sbom`, `vectispire-scan-${id}.sbom.json`);
    }

    /**
     * The three documents a scan produces and nobody could obtain.
     *
     * <p><b>The in-toto attestation and the two VEX documents were computed, served, and offered
     * nowhere.</b> They are precisely the pieces an assessor asks for from a scan: what produced
     * this result, and what the publisher says about each vulnerability. Three typed client methods
     * existed and were called by nothing; they are removed in favour of the path that suits a
     * download, the one the SBOM already takes.
     */
    downloadAttestation(id: number): void {
        this.download(`/api/v1/attestations/scans/${id}`, `vectispire-scan-${id}.attestation.json`);
    }

    downloadCsaf(id: number): void {
        this.download(`/api/v1/csaf/scans/${id}/csaf.json`, `vectispire-scan-${id}.csaf.json`);
    }

    downloadCycloneDx(id: number): void {
        this.download(`/api/v1/cyclonedx/scans/${id}/cyclonedx-vex.json`, `vectispire-scan-${id}.cyclonedx-vex.json`);
    }

    private download(path: string, filename: string): void {
        this.documentsApi.downloadDocument(path).subscribe({ next: (response) => saveDocument(response, filename) });
    }

    seconds(durationMs: number): number {
        return Math.round(durationMs / 100) / 10;
    }

    private load(id: number): void {
        this.scansApi.scan(id).subscribe({
            next: (detail) => this.scan.set(detail),
            error: (response) =>
                this.error.set(
                    response?.status === 404 ? this.i18n.t('scans.error_not_found') : this.i18n.t('scans.error_load')
                )
        });
    }
}
