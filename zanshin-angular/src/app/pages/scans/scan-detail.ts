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

@Component({
    selector: 'app-scan-detail',
    standalone: true,
    imports: [CommonModule, RouterLink, ButtonModule, CardModule, MessageModule, TableModule, TagModule, LastScanTag],
    template: `
        @if (scan(); as detail) {
            <div class="mb-4">
                <a routerLink="/repositories" class="text-sm">← Repositories</a>
                <h1 class="text-2xl font-semibold m-0 mt-1">Scan #{{ detail.id }} — {{ detail.targetName }}</h1>
                <p class="text-muted-color mt-1 mb-0">
                    {{ detail.branch }} · {{ detail.createdAt | date: 'dd/MM/yyyy HH:mm' }}
                    @if (detail.durationMs) {
                        · {{ seconds(detail.durationMs) }} s
                    }
                    <!-- Only when the tree carried a manifest this could read. A blank "Version:"
                          label would suggest the project has none, which is not what was found. -->
                    @if (detail.projectType) {
                        · {{ detail.projectType }}
                        @if (detail.projectVersion) {
                            {{ detail.projectVersion }}
                        }
                    }
                </p>
            </div>

            @if (detail.error) {
                <!-- Shown even on a completed scan: this is where the steps that looked at
                      nothing are recorded, and without this line an operator would believe the
                      scan complete. -->
                <p-message [severity]="detail.status === 'failed' ? 'error' : 'warn'" [closable]="false" styleClass="mb-4 w-full">
                    {{ detail.error }}
                </p-message>
            }

            <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
                <p-card>
                    <div class="text-muted-color text-sm">State</div>
                    <div class="mt-2"><app-last-scan [scan]="detail" /></div>
                </p-card>
                <p-card>
                    <div class="text-muted-color text-sm">Findings</div>
                    <div class="text-3xl font-semibold mt-1">{{ detail.findingsCount }}</div>
                </p-card>
                <p-card>
                    <div class="text-muted-color text-sm">New issues</div>
                    <div class="text-3xl font-semibold mt-1" [class.text-orange-500]="detail.newIssuesCount > 0">{{ detail.newIssuesCount }}</div>
                </p-card>
                <p-card>
                    <div class="text-muted-color text-sm">Resolved issues</div>
                    <div class="text-3xl font-semibold mt-1" [class.text-green-600]="detail.resolvedIssuesCount > 0">
                        {{ detail.resolvedIssuesCount }}
                    </div>
                </p-card>
            </div>

            @if (detail.hasSbom) {
                <!-- The flag existed and led nowhere: the payload announced an SBOM the interface
                      offered no way to fetch. -->
                <div class="mb-4">
                    <p-button
                        label="Download SBOM"
                        icon="pi pi-download"
                        severity="secondary"
                        size="small"
                        (onClick)="downloadSbom(detail.id)" />
                </div>
            }

            <p-card>
                <ng-template #title>
                    Findings from this scan
                    <span class="text-muted-color font-normal text-sm">
                        — what this scan observed, not the target's backlog
                    </span>
                </ng-template>

                @if (detail.findingsTruncated) {
                    <p-message severity="info" [closable]="false" styleClass="mb-3 w-full">
                        {{ detail.findingsTotal }} findings in total; the first {{ detail.findings.length }} are shown.
                    </p-message>
                }

                <p-table
                    [value]="detail.findings"
                    dataKey="id"
                    styleClass="p-datatable-sm"
                    [paginator]="detail.findings.length > 25"
                    [rows]="25"
                    [rowsPerPageOptions]="[25, 50, 100]">
                    <ng-template #header>
                        <tr>
                            <th style="width: 9rem">Type</th>
                            <th style="width: 7rem">Severity</th>
                            <th>Finding</th>
                            <th>Location</th>
                        </tr>
                    </ng-template>
                    <ng-template #body let-finding>
                        <tr>
                            <td>{{ typeLabel(finding.type) }}</td>
                            <td><p-tag [value]="finding.severity" [severity]="severityOf(finding.severity)" /></td>
                            <td>
                                <div class="font-medium">
                                    @if (finding.link) {
                                        <a [href]="finding.link" target="_blank" rel="noopener noreferrer">{{ finding.identifier }}</a>
                                    } @else {
                                        {{ finding.identifier }}
                                    }
                                </div>
                                @if (finding.description) {
                                    <div class="text-sm text-muted-color">{{ finding.description }}</div>
                                }
                                @if (finding.packageName) {
                                    <div class="text-sm text-muted-color">
                                        {{ finding.packageName }} {{ finding.packageVersion }}
                                        @if (finding.fixVersions) {
                                            · <span class="text-green-600">fixed in {{ finding.fixVersions }}</span>
                                        } @else {
                                            · <span class="text-muted-color">no published fix</span>
                                        }
                                    </div>
                                }
                            </td>
                            <td class="font-mono text-sm">
                                @if (finding.filePath) {
                                    {{ finding.filePath }}@if (finding.line) {<span>:{{ finding.line }}</span>}
                                } @else {
                                    <span class="text-muted-color font-sans">—</span>
                                }
                            </td>
                        </tr>
                    </ng-template>
                    <ng-template #emptymessage>
                        <tr><td colspan="4" class="text-center text-muted-color py-6">No finding.</td></tr>
                    </ng-template>
                </p-table>
            </p-card>
        } @else if (error(); as message) {
            <p-message severity="error" [closable]="false" styleClass="w-full">{{ message }}</p-message>
        } @else {
            <p class="text-muted-color">Loading…</p>
        }
    `
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
