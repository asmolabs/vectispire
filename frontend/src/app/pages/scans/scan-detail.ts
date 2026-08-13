import { CommonModule } from '@angular/common';
import { Component, effect, inject, input, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { CardModule } from '@openng/optimus-ui/card';
import { MessageModule } from '@openng/optimus-ui/message';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import { ApiService } from '../../core/api.service';
import type { ScanDetail } from '../../core/api.models';
import { LastScanTag } from '../../shared/last-scan';

/** Les types de constat, traduits. Table ouverte : un type inconnu s'affiche brut. */
const TYPE_LABELS: Record<string, string> = {
    vulnerability: 'Vulnérabilité',
    secret: 'Secret',
    iac: 'Infrastructure',
    license: 'Licence',
    eol: 'Fin de vie',
    sast: 'Code source',
    quality: 'Qualité'
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
    imports: [CommonModule, RouterLink, CardModule, MessageModule, TableModule, TagModule, LastScanTag],
    template: `
        @if (scan(); as detail) {
            <div class="mb-4">
                <a routerLink="/depots" class="text-sm">← Dépôts</a>
                <h1 class="text-2xl font-semibold m-0 mt-1">Scan #{{ detail.id }} — {{ detail.targetName }}</h1>
                <p class="text-muted-color mt-1 mb-0">
                    {{ detail.branch }} · {{ detail.createdAt | date: 'dd/MM/yyyy HH:mm' }}
                    @if (detail.durationMs) {
                        · {{ seconds(detail.durationMs) }} s
                    }
                </p>
            </div>

            @if (detail.error) {
                <!-- Affiché même sur un scan terminé : c'est là que se logent les étapes qui
                     n'ont rien regardé, et sans cette ligne l'opérateur croirait le scan
                     complet. -->
                <p-message [severity]="detail.status === 'failed' ? 'error' : 'warn'" [closable]="false" styleClass="mb-4 w-full">
                    {{ detail.error }}
                </p-message>
            }

            <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
                <p-card>
                    <div class="text-muted-color text-sm">État</div>
                    <div class="mt-2"><app-last-scan [scan]="detail" /></div>
                </p-card>
                <p-card>
                    <div class="text-muted-color text-sm">Constats</div>
                    <div class="text-3xl font-semibold mt-1">{{ detail.findingsCount }}</div>
                </p-card>
                <p-card>
                    <div class="text-muted-color text-sm">Nouveaux problèmes</div>
                    <div class="text-3xl font-semibold mt-1" [class.text-orange-500]="detail.newIssuesCount > 0">{{ detail.newIssuesCount }}</div>
                </p-card>
                <p-card>
                    <div class="text-muted-color text-sm">Problèmes résolus</div>
                    <div class="text-3xl font-semibold mt-1" [class.text-green-600]="detail.resolvedIssuesCount > 0">
                        {{ detail.resolvedIssuesCount }}
                    </div>
                </p-card>
            </div>

            <p-card>
                <ng-template #title>
                    Constats de ce scan
                    <span class="text-muted-color font-normal text-sm">
                        — ce que ce scan a observé, pas le backlog de la cible
                    </span>
                </ng-template>

                @if (detail.findingsTruncated) {
                    <p-message severity="info" [closable]="false" styleClass="mb-3 w-full">
                        {{ detail.findingsTotal }} constats au total ; les {{ detail.findings.length }} premiers sont affichés.
                    </p-message>
                }

                <p-table [value]="detail.findings" dataKey="id" styleClass="p-datatable-sm">
                    <ng-template #header>
                        <tr>
                            <th style="width: 9rem">Type</th>
                            <th style="width: 7rem">Sévérité</th>
                            <th>Constat</th>
                            <th>Emplacement</th>
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
                                            · <span class="text-green-600">corrigé en {{ finding.fixVersions }}</span>
                                        } @else {
                                            · <span class="text-muted-color">aucun correctif publié</span>
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
                        <tr><td colspan="4" class="text-center text-muted-color py-6">Aucun constat.</td></tr>
                    </ng-template>
                </p-table>
            </p-card>
        } @else if (error(); as message) {
            <p-message severity="error" [closable]="false" styleClass="w-full">{{ message }}</p-message>
        } @else {
            <p class="text-muted-color">Chargement…</p>
        }
    `
})
export class ScanDetailPage {
    private readonly api = inject(ApiService);

    readonly id = input.required<string>();
    readonly scan = signal<ScanDetail | null>(null);
    readonly error = signal<string | null>(null);

    constructor() {
        // Un `effect` et non un appel dans le constructeur : les entrées signal ne sont pas
        // encore liées à ce moment-là, et lire `id()` y lève NG0950 — l'écran restait sur
        // « Chargement… » sans rien dire. L'effet a en prime la bonne propriété : il suit
        // la navigation d'un scan à l'autre sans qu'on quitte l'écran.
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

    seconds(durationMs: number): number {
        return Math.round(durationMs / 100) / 10;
    }

    private load(id: number): void {
        this.api.scan(id).subscribe({
            next: (detail) => this.scan.set(detail),
            error: (response) => this.error.set(response?.status === 404 ? "Ce scan n'existe pas." : 'Impossible de charger ce scan.')
        });
    }
}
