import { CommonModule } from '@angular/common';
import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { CheckboxModule } from '@openng/optimus-ui/checkbox';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { InputNumberModule } from '@openng/optimus-ui/inputnumber';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { SelectModule } from '@openng/optimus-ui/select';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import { ApiService } from '../../core/api.service';
import type { ApiKeySummary } from '../../core/api.models';

/** Les portées, avec ce qu'elles autorisent — parce que « scan » et « agent » se
 *  ressemblent et que l'une des deux donne le droit d'exécuter du code. */
const SCOPES = [
    { value: 'read', label: 'Lecture', hint: 'Consulter les constats, scans et rapports.' },
    { value: 'scan', label: 'Déclencher un scan', hint: 'Mettre un scan en file sur une cible existante.' },
    { value: 'export', label: 'Export', hint: 'Récupérer SARIF, OpenVEX, SBOM.' },
    { value: 'agent', label: 'Agent', hint: "Réclamer et exécuter des scans. Ce périmètre exécute du code : ne l'accordez qu'à un agent." }
];

@Component({
    selector: 'app-api-keys',
    standalone: true,
    imports: [CommonModule, FormsModule, ButtonModule, CardModule, CheckboxModule, DialogModule, InputNumberModule, InputTextModule, MessageModule, SelectModule, TableModule, TagModule],
    template: `
        <div class="mb-4 flex items-start justify-between gap-4">
            <div>
                <h1 class="text-2xl font-semibold m-0">Clés d'API</h1>
                <p class="text-muted-color mt-1 mb-0">Les clés qui authentifient les appels automatisés.</p>
            </div>
            <p-button label="Émettre une clé" icon="pi pi-plus" (onClick)="openForm()" />
        </div>

        @if (error(); as message) {
            <p-message severity="error" [closable]="false" styleClass="mb-4 w-full">{{ message }}</p-message>
        }

        <p-card>
            <p-table [value]="keys()" [loading]="loading()" dataKey="id" styleClass="p-datatable-sm">
                <ng-template #header>
                    <tr>
                        <th>Nom</th>
                        <th>Préfixe</th>
                        <th>Portées</th>
                        <th>Cible</th>
                        <th>Dernier usage</th>
                        <th>Expiration</th>
                        <th class="w-1"></th>
                    </tr>
                </ng-template>
                <ng-template #body let-key>
                    <tr>
                        <td class="font-medium">{{ key.name }}</td>
                        <td class="font-mono text-sm whitespace-nowrap">{{ key.prefix }}…</td>
                        <td>
                            <div class="flex flex-wrap gap-1">
                                @for (scope of key.scopes; track scope) {
                                    <!-- « agent » en rouge : il donne le droit d'exécuter des scans,
                                         et se distingue mal de « scan » à la lecture. -->
                                    <p-tag [value]="scopeLabel(scope)" [severity]="scope === 'agent' ? 'danger' : 'secondary'" />
                                }
                            </div>
                        </td>
                        <td>
                            @if (key.targetLabel) {
                                <span class="text-sm">{{ key.targetLabel }}</span>
                            } @else {
                                <span class="text-muted-color">Toutes</span>
                            }
                        </td>
                        <td>
                            @if (key.lastUsedAt) {
                                {{ key.lastUsedAt | date: 'dd/MM/yyyy HH:mm' }}
                            } @else {
                                <!-- Jamais utilisée n'est pas rien : c'est souvent une clé émise
                                     pour un usage qui n'a jamais eu lieu, donc à révoquer. -->
                                <span class="text-muted-color">Jamais</span>
                            }
                        </td>
                        <td>
                            @if (key.isExpired) {
                                <p-tag value="Expirée" severity="danger" />
                            } @else if (key.expiresAt) {
                                {{ key.expiresAt | date: 'dd/MM/yyyy' }}
                            } @else {
                                <span class="text-muted-color">Sans limite</span>
                            }
                        </td>
                        <td class="text-right">
                            <p-button icon="pi pi-trash" severity="danger" [text]="true" [rounded]="true"
                                      [ariaLabel]="'Révoquer ' + key.name" (onClick)="askDelete(key)" />
                        </td>
                    </tr>
                </ng-template>
                <ng-template #emptymessage>
                    <tr><td colspan="7" class="text-center text-muted-color py-6">Aucune clé émise.</td></tr>
                </ng-template>
            </p-table>
        </p-card>

        <p-dialog header="Émettre une clé d'API" [(visible)]="formVisible" [modal]="true" [style]="{ width: '36rem' }">
            <div class="flex flex-col gap-4">
                <div class="flex flex-col gap-2">
                    <label for="name" class="font-medium">Nom</label>
                    <input pInputText id="name" [(ngModel)]="form.name" placeholder="Chaîne d'intégration" />
                    <small class="text-muted-color">Ce qui permettra de savoir laquelle révoquer.</small>
                </div>

                <div class="flex flex-col gap-2">
                    <span class="font-medium">Portées</span>
                    @for (scope of scopes; track scope.value) {
                        <div class="flex items-start gap-2">
                            <p-checkbox [inputId]="scope.value" [binary]="true" [ngModel]="form.scopes.includes(scope.value)"
                                        (ngModelChange)="toggleScope(scope.value, $event)" />
                            <label [for]="scope.value" class="cursor-pointer">
                                <span [class.text-red-500]="scope.value === 'agent'">{{ scope.label }}</span>
                                <span class="block text-sm text-muted-color">{{ scope.hint }}</span>
                            </label>
                        </div>
                    }
                </div>

                <div class="flex flex-col gap-2">
                    <label for="target" class="font-medium">Restreindre à une cible <span class="text-muted-color font-normal">(facultatif)</span></label>
                    <p-select id="target" [options]="targetOptions()" optionLabel="label" optionValue="value"
                              [(ngModel)]="form.target" [showClear]="true" placeholder="Toutes les cibles" styleClass="w-full" />
                </div>

                <div class="flex flex-col gap-2">
                    <label for="lifetime" class="font-medium">Expire dans <span class="text-muted-color font-normal">(facultatif)</span></label>
                    <p-inputnumber inputId="lifetime" [(ngModel)]="form.expiresInDays" [min]="1" [max]="3650" suffix=" jours" styleClass="w-full" />
                </div>

                @if (formError(); as message) {
                    <p-message severity="error" [closable]="false">{{ message }}</p-message>
                }
            </div>
            <ng-template #footer>
                <p-button label="Annuler" [text]="true" (onClick)="formVisible.set(false)" />
                <p-button label="Émettre" [loading]="saving()" (onClick)="submit()" />
            </ng-template>
        </p-dialog>

        <!-- La seule fois où la valeur existe. Fermer cette fenêtre la perd
             définitivement, et c'est dit avant, pas après. -->
        <p-dialog header="Clé émise" [(visible)]="secretVisible" [modal]="true" [closable]="false" [style]="{ width: '36rem' }">
            <p-message severity="warn" [closable]="false" styleClass="mb-4 w-full">
                Copiez-la maintenant : elle n'est stockée que sous forme d'empreinte et ne pourra pas être réaffichée.
            </p-message>
            <div class="font-mono text-sm p-3 border rounded break-all select-all" style="border-color: var(--surface-border)">{{ issuedSecret() }}</div>
            <ng-template #footer>
                <p-button label="J'ai copié la clé" (onClick)="dismissSecret()" />
            </ng-template>
        </p-dialog>

        <p-dialog header="Révoquer cette clé ?" [(visible)]="deleteVisible" [modal]="true" [style]="{ width: '30rem' }">
            @if (pendingDelete(); as key) {
                <p class="m-0">
                    <span class="font-medium">{{ key.name }}</span> cessera immédiatement de fonctionner. Tout appel
                    qui l'utilise échouera. C'est définitif.
                </p>
            }
            <ng-template #footer>
                <p-button label="Annuler" [text]="true" (onClick)="deleteVisible.set(false)" />
                <p-button label="Révoquer" severity="danger" [loading]="saving()" (onClick)="confirmDelete()" />
            </ng-template>
        </p-dialog>
    `
})
export class ApiKeys {
    private readonly api = inject(ApiService);
    readonly scopes = SCOPES;

    readonly keys = signal<ApiKeySummary[]>([]);
    readonly targetOptions = signal<{ label: string; value: string }[]>([]);
    readonly loading = signal(true);
    readonly saving = signal(false);
    readonly error = signal<string | null>(null);
    readonly formError = signal<string | null>(null);
    readonly formVisible = signal(false);
    readonly secretVisible = signal(false);
    readonly issuedSecret = signal<string | null>(null);
    readonly deleteVisible = signal(false);
    readonly pendingDelete = signal<ApiKeySummary | null>(null);

    form: { name: string; scopes: string[]; target: string | null; expiresInDays: number | null } = {
        name: '',
        scopes: ['read', 'scan', 'export'],
        target: null,
        expiresInDays: null
    };

    constructor() {
        this.reload();
        this.api.apiKeyTargets().subscribe({
            next: (targets) => {
                this.targetOptions.set([
                    ...targets.repositories.map((row) => ({ label: `Dépôt — ${row.label}`, value: `repository:${row.id}` })),
                    ...targets.containers.map((row) => ({ label: `Conteneur — ${row.label}`, value: `container:${row.id}` }))
                ]);
            },
            // Silencieux : sans la liste, le champ reste vide et la clé porte sur toutes
            // les cibles. C'est dégradé, pas cassé — inutile d'alarmer.
            error: () => this.targetOptions.set([])
        });
    }

    reload(preserveError = false): void {
        this.loading.set(true);
        this.api.apiKeys().subscribe({
            next: (keys) => {
                this.keys.set(keys);
                if (!preserveError) this.error.set(null);
                this.loading.set(false);
            },
            error: () => {
                this.error.set('Impossible de charger la liste des clés.');
                this.loading.set(false);
            }
        });
    }

    scopeLabel(scope: string): string {
        return SCOPES.find((entry) => entry.value === scope)?.label ?? scope;
    }

    toggleScope(scope: string, checked: boolean): void {
        this.form.scopes = checked ? [...this.form.scopes, scope] : this.form.scopes.filter((value) => value !== scope);
    }

    openForm(): void {
        this.form = { name: '', scopes: ['read', 'scan', 'export'], target: null, expiresInDays: null };
        this.formError.set(null);
        this.formVisible.set(true);
    }

    submit(): void {
        const [targetKind, targetId] = this.form.target ? this.form.target.split(':') : [undefined, undefined];
        this.saving.set(true);
        this.api
            .createApiKey({
                name: this.form.name.trim(),
                scopes: this.form.scopes,
                target_kind: targetKind,
                target_id: targetId === undefined ? undefined : Number(targetId),
                expires_in_days: this.form.expiresInDays ?? undefined
            })
            .subscribe({
                next: (issued) => {
                    this.saving.set(false);
                    this.formVisible.set(false);
                    this.issuedSecret.set(issued.secret);
                    this.secretVisible.set(true);
                    this.reload();
                },
                error: (response) => {
                    this.saving.set(false);
                    this.formError.set(response?.error?.message ?? "Impossible d'émettre cette clé.");
                }
            });
    }

    dismissSecret(): void {
        // Effacée du modèle en même temps que de l'écran : la garder en mémoire pour rien
        // laisserait la valeur accessible dans l'onglet ouvert.
        this.issuedSecret.set(null);
        this.secretVisible.set(false);
    }

    askDelete(key: ApiKeySummary): void {
        this.pendingDelete.set(key);
        this.deleteVisible.set(true);
    }

    confirmDelete(): void {
        const key = this.pendingDelete();
        if (!key) return;
        this.saving.set(true);
        this.api.deleteApiKey(key.id).subscribe({
            next: () => {
                this.saving.set(false);
                this.deleteVisible.set(false);
                this.reload();
            },
            error: (response) => {
                this.saving.set(false);
                this.deleteVisible.set(false);
                this.error.set(response?.error?.message ?? 'La révocation a échoué.');
                this.reload(true);
            }
        });
    }
}
