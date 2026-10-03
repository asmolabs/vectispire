import { DatePipe } from '@angular/common';
import { Component, effect, inject, input, signal, untracked, ChangeDetectionStrategy } from '@angular/core';
import { RouterLink } from '@angular/router';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { MessageModule } from '@openng/optimus-ui/message';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import { DocumentsApi } from '../../core/api/documents.api';
import { ScansApi } from '../../core/api/scans.api';
import { I18nService } from '../../core/i18n/i18n.service';
import { LatestRequest } from '../../core/latest-request';
import { saveDocument } from '../../core/download';
import type { PluginRefusal, ScanDetail, ScanSummary } from '../../core/api.models';
import { keyFor } from '../../core/i18n/literal-keys';
import { LastScanTag } from '../../shared/last-scan';
import { RuleCoverageBanner } from '../../shared/rule-coverage-banner';
import { findingTypeLabel, findingTypeOptions, isToolProvenance } from '../../shared/finding-types';
import type { FindingTypeOption } from '../../shared/finding-types';

const SEVERITY_SEVERITY: Record<string, 'danger' | 'warn' | 'secondary'> = {
    critical: 'danger',
    high: 'danger',
    medium: 'warn',
    low: 'secondary',
    negligible: 'secondary',
    unknown: 'secondary'
};

import { TranslatePipe } from '../../core/i18n/translate.pipe';

/**
 * Why a plugin's report was refused, through literal keys (decision 0019): the tag used to build
 * `'scans.plugin_refusal.' + refusal`, which the i18n check could not see. A reason this client does
 * not know — or none — still reads as a refusal, never as a key path.
 */
export const PLUGIN_REFUSAL_KEYS = {
    unsigned: 'scans.plugin_refusal.unsigned',
    signature_unverified: 'scans.plugin_refusal.signature_unverified'
} as const satisfies Record<PluginRefusal, string>;

/**
 * Which built-in steps looked at the tree (decision 0032). `unrecorded` is a scan from before the
 * control plane kept it — never "examined nothing", which is `recorded` with an empty `examined`.
 */
export type Examination =
    { state: 'unrecorded' } | { state: 'recorded'; examined: FindingTypeOption[]; notExamined: FindingTypeOption[] };

@Component({
    selector: 'app-scan-detail',
    imports: [
        DatePipe,
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

    /**
     * The detail's request. Following a link from one scan to another keeps this screen and only
     * changes `id`: without cancelling, the first scan's answer could land after the second's and
     * put scan 34's findings under the address of scan 35.
     */
    private readonly detailRequest = new LatestRequest();

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
            if (Number.isFinite(id)) untracked(() => this.load(id));
        });
    }

    refusalLabel(refusal: string | null): string {
        return this.i18n.t(keyFor(PLUGIN_REFUSAL_KEYS, refusal) ?? 'scans.plugin_state.refused');
    }

    typeLabel(type: string): string {
        return findingTypeLabel(this.i18n, type);
    }

    /** A digest shortened like an image's: enough to compare two scans, not enough to crush a row. */
    shortDigest(digest: string | null): string {
        return digest ? digest.slice(0, 12) : '—';
    }

    /**
     * What the scan examined, or null where there is nothing to say: a scan still waiting or running
     * has examined nothing yet, and one that failed before running shows its error instead.
     *
     * **Null from the server is "not recorded", and it is said.** Read as an empty list, a scan from
     * before the upgrade would show every step as not examined — telling an assessor that a tree was
     * never searched for secrets, when nothing wrote down whether it was.
     */
    examination(detail: ScanDetail): Examination | null {
        const recorded = detail.examinedTypes;
        if (recorded === null || recorded === undefined) {
            return detail.scan.status === 'completed' ? { state: 'unrecorded' } : null;
        }
        const builtIn = findingTypeOptions(this.i18n).filter((option) => !isToolProvenance(option.value));
        const known = new Set(builtIn.map((option) => option.value));
        return {
            state: 'recorded',
            // A name this screen does not know yet is shown raw rather than dropped: it did examine.
            examined: [
                ...builtIn.filter((option) => recorded.includes(option.value)),
                ...recorded.filter((type) => !known.has(type)).map((type) => ({ value: type, label: type }))
            ],
            notExamined: builtIn.filter((option) => !recorded.includes(option.value))
        };
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

    /**
     * When a waiting scan may be claimed again, or null: only for a scan still `pending` whose
     * `notBefore` is ahead. Past it, the scan is simply queued — saying "retry at" a moment already
     * gone would read as a scan stuck on a schedule.
     */
    retryAt(scan: ScanSummary, now: number = Date.now()): string | null {
        if (scan.status !== 'pending' || !scan.notBefore) return null;
        const at = Date.parse(scan.notBefore);
        return Number.isFinite(at) && at > now ? scan.notBefore : null;
    }

    seconds(durationMs: number): number {
        return Math.round(durationMs / 100) / 10;
    }

    private load(id: number): void {
        // The previous scan is cleared first: left in place, it would stay on screen under the new
        // address until the answer came — or for good, if the new one failed beside its error.
        this.scan.set(null);
        this.error.set(null);
        this.detailRequest.run(this.scansApi.scan(id), {
            next: (detail) => this.scan.set(detail),
            error: (response) =>
                this.error.set(
                    (response as { status?: number } | null)?.status === 404
                        ? this.i18n.t('scans.error_not_found')
                        : this.i18n.t('scans.error_load')
                )
        });
    }
}
