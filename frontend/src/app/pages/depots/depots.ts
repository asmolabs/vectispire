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
import type { MonitoredRepository } from '../../core/api.models';
import { SessionStore } from '../../core/session.store';
import { LastScanTag } from '../../shared/last-scan';

@Component({
    selector: 'app-depots',
    standalone: true,
    imports: [CommonModule, FormsModule, RouterLink, ButtonModule, CardModule, DialogModule, InputTextModule, MessageModule, TableModule, LastScanTag],
    template: `
        <div class="mb-4 flex items-start justify-between gap-4">
            <div>
                <h1 class="text-2xl font-semibold m-0">Dépôts</h1>
                <p class="text-muted-color mt-1 mb-0">Les dépôts git surveillés et l'état de leur dernier scan.</p>
            </div>
            @if (isAdmin()) {
                <p-button label="Ajouter un dépôt" icon="pi pi-plus" (onClick)="openForm()" />
            }
        </div>

        @if (error(); as message) {
            <p-message severity="error" [closable]="false" styleClass="mb-4 w-full">{{ message }}</p-message>
        }
        @if (notice(); as message) {
            <p-message severity="success" [closable]="false" styleClass="mb-4 w-full">{{ message }}</p-message>
        }

        <p-card>
            <p-table [value]="repositories()" [loading]="loading()" dataKey="id" styleClass="p-datatable-sm">
                <ng-template #header>
                    <tr>
                        <th>Dépôt</th>
                        <th>Branche</th>
                        <th>Dernier scan</th>
                        <th class="text-right">À traiter</th>
                        @if (isAdmin()) { <th class="w-1"></th> }
                    </tr>
                </ng-template>
                <ng-template #body let-repository>
                    <tr>
                        <td>
                            <div class="font-medium">{{ repository.displayName }}</div>
                            <div class="text-sm text-muted-color break-all">{{ repository.url }}</div>
                        </td>
                        <td>{{ repository.branch }}</td>
                        <td>
                            @if (repository.lastScan; as scan) {
                                <a [routerLink]="['/scans', scan.id]"><app-last-scan [scan]="scan" /></a>
                            } @else {
                                <app-last-scan [scan]="null" />
                            }
                        </td>
                        <td class="text-right">
                            @if (repository.openIssues > 0) {
                                <a [routerLink]="['/issues']" [queryParams]="{ repo_id: repository.id }" class="font-medium">{{ repository.openIssues }}</a>
                            } @else {
                                <span class="text-muted-color">0</span>
                            }
                        </td>
                        @if (isAdmin()) {
                            <td class="text-right whitespace-nowrap">
                                <p-button icon="pi pi-play" [text]="true" [rounded]="true"
                                          [ariaLabel]="'Lancer un scan de ' + repository.url"
                                          [disabled]="busy() === repository.id" (onClick)="triggerScan(repository)" />
                                <p-button icon="pi pi-trash" severity="danger" [text]="true" [rounded]="true"
                                          [ariaLabel]="'Supprimer ' + repository.url" (onClick)="askDelete(repository)" />
                            </td>
                        }
                    </tr>
                </ng-template>
                <ng-template #emptymessage>
                    <tr><td [attr.colspan]="isAdmin() ? 5 : 4" class="text-center text-muted-color py-6">Aucun dépôt surveillé.</td></tr>
                </ng-template>
            </p-table>
        </p-card>

        <p-dialog header="Ajouter un dépôt" [(visible)]="formVisible" [modal]="true" [style]="{ width: '32rem' }">
            <div class="flex flex-col gap-4">
                <div class="flex flex-col gap-2">
                    <label for="url" class="font-medium">URL du dépôt</label>
                    <input pInputText id="url" [(ngModel)]="form.url" placeholder="https://github.com/org/projet.git" />
                    <small class="text-muted-color">https://…, ssh://… ou git&#64;hôte:chemin</small>
                </div>
                <div class="flex flex-col gap-2">
                    <label for="branch" class="font-medium">Branche</label>
                    <input pInputText id="branch" [(ngModel)]="form.branch" placeholder="main" />
                </div>
                <div class="flex flex-col gap-2">
                    <label for="name" class="font-medium">Nom affiché <span class="text-muted-color font-normal">(facultatif)</span></label>
                    <input pInputText id="name" [(ngModel)]="form.name" />
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

        <p-dialog header="Supprimer ce dépôt ?" [(visible)]="deleteVisible" [modal]="true" [style]="{ width: '30rem' }">
            @if (pendingDelete(); as repository) {
                <p class="m-0">
                    <span class="font-medium">{{ repository.url }}</span> et tout son historique — scans, constats et
                    {{ repository.openIssues }} problème(s) à traiter — seront supprimés. C'est définitif.
                </p>
            }
            <ng-template #footer>
                <p-button label="Annuler" [text]="true" (onClick)="deleteVisible.set(false)" />
                <p-button label="Supprimer" severity="danger" [loading]="saving()" (onClick)="confirmDelete()" />
            </ng-template>
        </p-dialog>
    `
})
export class Depots {
    private readonly api = inject(ApiService);
    private readonly session = inject(SessionStore);

    readonly repositories = signal<MonitoredRepository[]>([]);
    readonly loading = signal(true);
    readonly saving = signal(false);
    readonly error = signal<string | null>(null);
    readonly formError = signal<string | null>(null);
    readonly formVisible = signal(false);
    readonly deleteVisible = signal(false);
    readonly pendingDelete = signal<MonitoredRepository | null>(null);
    /** La ligne dont le scan est en cours de mise en file. */
    readonly busy = signal<number | null>(null);
    readonly notice = signal<string | null>(null);
    readonly isAdmin = this.session.isAdmin;

    form = { url: '', branch: 'main', name: '' };

    constructor() {
        this.reload();
    }

    reload(): void {
        this.loading.set(true);
        this.api.repositories().subscribe({
            next: (repositories) => {
                this.repositories.set(repositories);
                this.error.set(null);
                this.loading.set(false);
            },
            error: () => {
                this.error.set('Impossible de charger la liste des dépôts.');
                this.loading.set(false);
            }
        });
    }

    /**
     * Met un scan en file. **Ne l'exécute pas** : un travailleur le réclamera.
     *
     * L'écran le dit, parce que l'attente qui suit n'est pas celle d'un bouton ordinaire —
     * sans cette phrase, l'absence de changement immédiat se lit comme un échec.
     */
    triggerScan(repository: MonitoredRepository): void {
        this.busy.set(repository.id);
        this.notice.set(null);
        this.api.triggerRepositoryScan(repository.id).subscribe({
            next: () => {
                this.busy.set(null);
                this.notice.set(`Scan mis en file pour ${repository.displayName}. Il démarrera dès qu'un travailleur sera disponible.`);
                this.reload();
            },
            error: (response) => {
                this.busy.set(null);
                // Le serveur sait pourquoi — « un scan est déjà en file », le plus souvent.
                this.error.set(response?.error?.message ?? 'Impossible de mettre ce scan en file.');
            }
        });
    }

    openForm(): void {
        this.form = { url: '', branch: 'main', name: '' };
        this.formError.set(null);
        this.formVisible.set(true);
    }

    submit(): void {
        this.saving.set(true);
        this.api.createRepository({ url: this.form.url.trim(), branch: this.form.branch.trim() || 'main', name: this.form.name.trim() || undefined }).subscribe({
            next: () => {
                this.saving.set(false);
                this.formVisible.set(false);
                this.reload();
            },
            error: (response) => {
                this.saving.set(false);
                // Le message du serveur est celui qui sait *pourquoi* — schéma refusé,
                // hôte absent. Le remplacer par un « erreur » générique perdrait l'info.
                this.formError.set(response?.error?.message ?? "Impossible d'ajouter ce dépôt.");
            }
        });
    }

    askDelete(repository: MonitoredRepository): void {
        this.pendingDelete.set(repository);
        this.deleteVisible.set(true);
    }

    confirmDelete(): void {
        const repository = this.pendingDelete();
        if (!repository) return;
        this.saving.set(true);
        this.api.deleteRepository(repository.id).subscribe({
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
