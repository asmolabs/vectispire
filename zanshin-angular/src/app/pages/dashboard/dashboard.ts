import { CommonModule } from '@angular/common';
import { Component, computed, inject, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { CardModule } from '@openng/optimus-ui/card';
import { MessageModule } from '@openng/optimus-ui/message';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import { ApiService } from '../../core/api.service';
import type { DashboardOverview } from '../../core/api.models';
import { LastScanTag } from '../../shared/last-scan';

/** Les sévérités dans l'ordre décroissant, avec leur couleur. Ordre fixe et non tiré des
 *  données : sinon deux chargements successifs peuvent les présenter différemment. */
const SEVERITIES = [
    { key: 'critical', label: 'Critique', severity: 'danger' as const },
    { key: 'high', label: 'Élevée', severity: 'warn' as const },
    { key: 'medium', label: 'Moyenne', severity: 'secondary' as const },
    { key: 'low', label: 'Faible', severity: 'secondary' as const }
];

@Component({
    selector: 'app-dashboard',
    standalone: true,
    imports: [CommonModule, RouterLink, CardModule, MessageModule, TableModule, TagModule, LastScanTag],
    template: `
        <div class="mb-4">
            <h1 class="text-2xl font-semibold m-0">Tableau de bord</h1>
            <p class="text-muted-color mt-1 mb-0">L'état de la surveillance, en une page.</p>
        </div>

        @if (error(); as message) {
            <p-message severity="error" [closable]="false" styleClass="mb-4 w-full">{{ message }}</p-message>
        }

        @if (data(); as overview) {
            <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4 mb-4">
                <p-card>
                    <div class="text-muted-color text-sm">Cibles en échec</div>
                    <div class="text-3xl font-semibold mt-1" [class.text-red-500]="overview.posture.failingCount > 0">
                        {{ overview.posture.failingCount }}<span class="text-muted-color text-lg font-normal"> / {{ overview.posture.totalCount }}</span>
                    </div>
                    <a routerLink="/securite" class="text-sm">Voir la posture</a>
                </p-card>

                <p-card>
                    <div class="text-muted-color text-sm">Vulnérabilités activement exploitées</div>
                    <div class="text-3xl font-semibold mt-1" [class.text-red-500]="overview.posture.kevCount > 0">{{ overview.posture.kevCount }}</div>
                    <a [routerLink]="['/issues']" [queryParams]="{ is_kev: true }" class="text-sm">Voir le catalogue KEV</a>
                </p-card>

                <p-card>
                    <div class="text-muted-color text-sm">Jamais scannées</div>
                    <div class="text-3xl font-semibold mt-1" [class.text-orange-500]="overview.posture.neverScannedCount > 0">
                        {{ overview.posture.neverScannedCount }}
                    </div>
                    <!-- Le chiffre le plus facile à confondre avec une bonne nouvelle :
                         une cible sans constat n'est pas une cible sans problème. -->
                    <div class="text-sm text-muted-color">Sans constat faute d'observation</div>
                </p-card>

                <p-card>
                    <div class="text-muted-color text-sm">Dernier scan en échec</div>
                    <div class="text-3xl font-semibold mt-1" [class.text-orange-500]="overview.posture.lastScanFailedCount > 0">
                        {{ overview.posture.lastScanFailedCount }}
                    </div>
                    <div class="text-sm text-muted-color">Données possiblement périmées</div>
                </p-card>
            </div>

            <div class="grid grid-cols-1 xl:grid-cols-3 gap-4">
                <p-card styleClass="xl:col-span-1">
                    <ng-template #title>Problèmes à traiter</ng-template>
                    <div class="flex flex-col gap-3">
                        @for (level of severities; track level.key) {
                            <div class="flex items-center justify-between">
                                <p-tag [value]="level.label" [severity]="level.severity" />
                                <a [routerLink]="['/issues']" [queryParams]="{ severity: level.key, state: 'open' }" class="text-xl font-semibold">
                                    {{ overview.backlogBySeverity[level.key] ?? 0 }}
                                </a>
                            </div>
                        }
                    </div>

                    <!-- Séparé, et dit : mêler la qualité au backlog de sécurité ferait
                         passer ce panneau à quatre chiffres le jour de la mise en service
                         du SAST, et plus personne ne le regarderait. -->
                    <div class="border-t mt-4 pt-3" style="border-color: var(--surface-border)">
                        <div class="flex items-center justify-between">
                            <span class="text-muted-color text-sm">Qualité <span class="text-xs">(ne bloque jamais)</span></span>
                            <a routerLink="/qualite" class="font-semibold">{{ overview.qualityTotal }}</a>
                        </div>
                    </div>
                </p-card>

                <p-card styleClass="xl:col-span-2">
                    <ng-template #title>Cibles en échec</ng-template>
                    @if (overview.failing.length === 0) {
                        <p class="text-muted-color m-0">Aucune cible ne viole sa politique.</p>
                        @if (overview.posture.neverScannedCount > 0) {
                            <p class="text-muted-color text-sm mt-2 mb-0">
                                {{ overview.posture.neverScannedCount }} cible(s) n'ont jamais été scannées : leur conformité n'est pas établie.
                            </p>
                        }
                    } @else {
                        <p-table [value]="overview.failing" styleClass="p-datatable-sm">
                            <ng-template #header>
                                <tr><th>Cible</th><th>Règle en cause</th><th class="text-right">Éléments</th></tr>
                            </ng-template>
                            <ng-template #body let-target>
                                <tr>
                                    <td>
                                        <div class="font-medium">{{ target.name }}</div>
                                        <div class="text-sm text-muted-color">{{ target.kind === 'repository' ? 'Dépôt' : 'Conteneur' }}</div>
                                    </td>
                                    <td>
                                        @for (violation of firstViolations(target.violations); track $index) {
                                            <div class="text-sm">
                                                <p-tag [value]="violation.rule === 'kev' ? 'KEV' : 'Sévérité'" severity="danger" styleClass="mr-2" />
                                                {{ violation.reason }}
                                            </div>
                                        }
                                        @if (target.violations.length > 3) {
                                            <div class="text-sm text-muted-color mt-1">et {{ target.violations.length - 3 }} autre(s)</div>
                                        }
                                    </td>
                                    <td class="text-right font-semibold">{{ target.violations.length }}</td>
                                </tr>
                            </ng-template>
                        </p-table>
                    }
                </p-card>
            </div>

            <p-card styleClass="mt-4">
                <ng-template #title>Scans récents</ng-template>
                <p-table [value]="overview.recentScans" styleClass="p-datatable-sm">
                    <ng-template #header>
                        <tr><th>Cible</th><th>État</th><th class="text-right">Constats</th></tr>
                    </ng-template>
                    <ng-template #body let-scan>
                        <tr>
                            <td>
                                <a [routerLink]="['/scans', scan.id]">{{ scan.repoId ? 'Dépôt ' + scan.repoId : 'Conteneur ' + scan.containerId }}</a>
                            </td>
                            <td><app-last-scan [scan]="scan" /></td>
                            <td class="text-right">{{ scan.findingsCount ?? '—' }}</td>
                        </tr>
                    </ng-template>
                    <ng-template #emptymessage>
                        <tr><td colspan="3" class="text-center text-muted-color py-6">Aucun scan.</td></tr>
                    </ng-template>
                </p-table>
            </p-card>
        } @else if (loading()) {
            <p class="text-muted-color">Chargement…</p>
        }
    `
})
export class Dashboard {
    private readonly api = inject(ApiService);
    readonly severities = SEVERITIES;

    readonly data = signal<DashboardOverview | null>(null);
    readonly loading = signal(true);
    readonly error = signal<string | null>(null);

    constructor() {
        this.api.dashboard().subscribe({
            next: (overview) => {
                this.data.set(overview);
                this.loading.set(false);
            },
            error: () => {
                this.error.set('Impossible de charger le tableau de bord.');
                this.loading.set(false);
            }
        });
    }

    /** Trois violations au plus : au-delà, la ligne devient un mur de texte et le tableau
     *  cesse de servir à repérer quoi traiter. */
    firstViolations(violations: DashboardOverview['failing'][number]['violations']) {
        return violations.slice(0, 3);
    }
}
