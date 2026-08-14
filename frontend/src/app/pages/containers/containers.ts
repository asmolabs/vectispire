import { CommonModule } from '@angular/common';
import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { TableModule } from '@openng/optimus-ui/table';
import { ApiService } from '../../core/api.service';
import type { MonitoredContainer } from '../../core/api.models';
import { SessionStore } from '../../core/session.store';
import { LastScanTag } from '../../shared/last-scan';

@Component({
    selector: 'app-containers',
    standalone: true,
    imports: [CommonModule, FormsModule, RouterLink, ButtonModule, CardModule, DialogModule, InputTextModule, MessageModule, TableModule, LastScanTag],
    template: `
        <div class="mb-4 flex items-start justify-between gap-4">
            <div>
                <h1 class="text-2xl font-semibold m-0">Conteneurs</h1>
                <p class="text-muted-color mt-1 mb-0">Les images de conteneur surveillées et l'état de leur dernier scan.</p>
            </div>
            @if (isAdmin()) {
                <p-button label="Ajouter une image" icon="pi pi-plus" (onClick)="openForm()" />
            }
        </div>

        <p-message severity="info" [closable]="false" styleClass="mb-4 w-full">
            Le déclenchement d'un scan depuis l'interface n'est pas encore disponible : la file de scans
            n'est pas portée. Les scans planifiés et ceux lancés par un agent continuent de fonctionner.
        </p-message>

        @if (error(); as message) {
            <p-message severity="error" [closable]="false" styleClass="mb-4 w-full">{{ message }}</p-message>
        }

        <p-card>
            <p-table [value]="containers()" [loading]="loading()" dataKey="id" styleClass="p-datatable-sm">
                <ng-template #header>
                    <tr>
                        <th>Image</th>
                        <th>Étiquette</th>
                        <th>Dernier scan</th>
                        <th class="text-right">À traiter</th>
                        @if (isAdmin()) { <th class="w-1"></th> }
                    </tr>
                </ng-template>
                <ng-template #body let-container>
                    <tr>
                        <td>
                            <div class="font-medium">{{ container.imageName }}</div>
                            <div class="text-sm text-muted-color" [title]="container.reference">{{ shorten(container.reference) }}</div>
                        </td>
                        <td class="font-mono text-sm whitespace-nowrap" [title]="container.tag">{{ shorten(container.tag) }}</td>
                        <td><app-last-scan [scan]="container.lastScan" /></td>
                        <td class="text-right">
                            @if (container.openIssues > 0) {
                                <a [routerLink]="['/issues']" [queryParams]="{ container_id: container.id }" class="font-medium">{{ container.openIssues }}</a>
                            } @else {
                                <span class="text-muted-color">0</span>
                            }
                        </td>
                        @if (isAdmin()) {
                            <td class="text-right">
                                <p-button icon="pi pi-trash" severity="danger" [text]="true" [rounded]="true"
                                          [ariaLabel]="'Supprimer ' + container.reference" (onClick)="askDelete(container)" />
                            </td>
                        }
                    </tr>
                </ng-template>
                <ng-template #emptymessage>
                    <tr><td [attr.colspan]="isAdmin() ? 5 : 4" class="text-center text-muted-color py-6">Aucune image surveillée.</td></tr>
                </ng-template>
            </p-table>
        </p-card>

        <p-dialog header="Ajouter une image" [(visible)]="formVisible" [modal]="true" [style]="{ width: '32rem' }">
            <div class="flex flex-col gap-4">
                <div class="flex flex-col gap-2">
                    <label for="registry" class="font-medium">Registre <span class="text-muted-color font-normal">(facultatif)</span></label>
                    <input pInputText id="registry" [(ngModel)]="form.registry" placeholder="ghcr.io" />
                    <small class="text-muted-color">Vide pour le registre par défaut.</small>
                </div>
                <div class="flex flex-col gap-2">
                    <label for="image" class="font-medium">Nom de l'image</label>
                    <input pInputText id="image" [(ngModel)]="form.imageName" placeholder="equipe/service" />
                </div>
                <div class="flex flex-col gap-2">
                    <label for="tag" class="font-medium">Étiquette</label>
                    <input pInputText id="tag" [(ngModel)]="form.tag" placeholder="latest" />
                    <small class="text-muted-color">Une étiquette, ou un condensé « sha256:… » pour figer la version scannée.</small>
                </div>
                <div class="flex flex-col gap-2">
                    <label for="agent-label" class="font-medium">Agent exigé <span class="text-muted-color font-normal">(facultatif)</span></label>
                    <input pInputText id="agent-label" [(ngModel)]="form.requiredAgentLabel" placeholder="réseau-client" />
                    <small class="text-muted-color">
                        L'étiquette qu'un agent doit porter pour scanner cette cible — et donc pour en recevoir
                        la clé de déploiement. Laissé vide, n'importe quel agent peut la prendre.
                    </small>
                </div>
                @if (formError(); as message) {
                    <p-message severity="error" [closable]="false">{{ message }}</p-message>
                }
            </div>
            <ng-template #footer>
                <p-button label="Annuler" [text]="true" (onClick)="formVisible.set(false)" />
                <p-button label="Ajouter" [loading]="saving()" (onClick)="submit()" />
            </ng-template>
        </p-dialog>

        <p-dialog header="Supprimer cette image ?" [(visible)]="deleteVisible" [modal]="true" [style]="{ width: '30rem' }">
            @if (pendingDelete(); as container) {
                <p class="m-0">
                    <span class="font-medium">{{ container.reference }}</span> et tout son historique — scans, constats et
                    {{ container.openIssues }} problème(s) à traiter — seront supprimés. C'est définitif.
                </p>
            }
            <ng-template #footer>
                <p-button label="Annuler" [text]="true" (onClick)="deleteVisible.set(false)" />
                <p-button label="Supprimer" severity="danger" [loading]="saving()" (onClick)="confirmDelete()" />
            </ng-template>
        </p-dialog>
    `
})
export class Containers {
    private readonly api = inject(ApiService);
    private readonly session = inject(SessionStore);

    readonly containers = signal<MonitoredContainer[]>([]);
    readonly loading = signal(true);
    readonly saving = signal(false);
    readonly error = signal<string | null>(null);
    readonly formError = signal<string | null>(null);
    readonly formVisible = signal(false);
    readonly deleteVisible = signal(false);
    readonly pendingDelete = signal<MonitoredContainer | null>(null);
    readonly isAdmin = this.session.isAdmin;

    form = { registry: '', imageName: '', tag: 'latest', requiredAgentLabel: '' };

    /**
     * Abrège un condensé pour l'affichage, la valeur entière restant dans l'infobulle.
     *
     * Sans cela, les 64 caractères hexadécimaux élargissent leur colonne jusqu'à écraser
     * toutes les autres — la table devient illisible pour *tous* les conteneurs dès qu'un
     * seul est épinglé par condensé. Ça ne se voit qu'à l'écran.
     */
    shorten(value: string): string {
        const match = /sha256:([a-f0-9]{64})/.exec(value);
        return match ? value.replace(match[1], match[1].slice(0, 12) + '…') : value;
    }

    constructor() {
        this.reload();
    }

    reload(): void {
        this.loading.set(true);
        this.api.containers().subscribe({
            next: (containers) => {
                this.containers.set(containers);
                this.error.set(null);
                this.loading.set(false);
            },
            error: () => {
                this.error.set('Impossible de charger la liste des conteneurs.');
                this.loading.set(false);
            }
        });
    }

    openForm(): void {
        this.form = { registry: '', imageName: '', tag: 'latest', requiredAgentLabel: '' };
        this.formError.set(null);
        this.formVisible.set(true);
    }

    submit(): void {
        this.saving.set(true);
        this.api
            .createContainer({
                registry: this.form.registry.trim() || undefined,
                image_name: this.form.imageName.trim(),
                tag: this.form.tag.trim() || 'latest',
                required_agent_label: this.form.requiredAgentLabel.trim() || undefined
            })
            .subscribe({
                next: () => {
                    this.saving.set(false);
                    this.formVisible.set(false);
                    this.reload();
                },
                error: (response) => {
                    this.saving.set(false);
                    // Le message du serveur est celui qui sait *pourquoi* — majuscules
                    // refusées, condensé mal formé. Le remplacer perdrait l'information.
                    this.formError.set(response?.error?.message ?? "Impossible d'ajouter cette image.");
                }
            });
    }

    askDelete(container: MonitoredContainer): void {
        this.pendingDelete.set(container);
        this.deleteVisible.set(true);
    }

    confirmDelete(): void {
        const container = this.pendingDelete();
        if (!container) return;
        this.saving.set(true);
        this.api.deleteContainer(container.id).subscribe({
            next: () => {
                this.saving.set(false);
                this.deleteVisible.set(false);
                this.reload();
            },
            error: () => {
                this.saving.set(false);
                this.deleteVisible.set(false);
                this.error.set('La suppression a échoué.');
            }
        });
    }
}
