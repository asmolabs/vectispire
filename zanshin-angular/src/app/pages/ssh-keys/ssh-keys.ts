import { CommonModule } from '@angular/common';
import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import { TextareaModule } from '@openng/optimus-ui/textarea';
import { TooltipModule } from '@openng/optimus-ui/tooltip';
import { ApiService } from '../../core/api.service';
import type { EncryptionState, SshKeySummary } from '../../core/api.models';

/**
 * L'état de chiffrement mérite une colonne, pas une ligne de journal.
 *
 * Une clé lisible seulement sous une clé de chiffrement précédente n'a pas fini d'être
 * tournée. Une clé qu'aucune clé configurée ne lit fera échouer le prochain clone qui en
 * a besoin — au moment du scan, dans un fil d'exécution, des heures plus tard, avec un
 * message qui ressemblera à un problème de réseau.
 */
const ENCRYPTION_LABELS: Record<EncryptionState, { label: string; severity: 'success' | 'warn' | 'danger'; hint: string }> = {
    current: { label: 'OK', severity: 'success', hint: "Chiffrée avec la clé de chiffrement courante." },
    previous_key: {
        label: 'À faire tourner',
        severity: 'warn',
        hint:
            "Chiffrée avec une clé de chiffrement précédente. Réenregistrez-la pour la passer sous ENCRYPTION_KEY — " +
            "et si elle date de la clé par défaut publiée dans le dépôt, sa moitié privée est publique : générez une nouvelle paire."
    },
    unreadable: {
        label: 'Illisible',
        severity: 'danger',
        hint:
            "Aucune clé configurée ne déchiffre cette valeur : le prochain clone qui en a besoin échouera. " +
            'Renseignez la clé précédente dans ZANSHIN_PREVIOUS_ENCRYPTION_KEYS, ou remplacez cette clé SSH.'
    }
};

@Component({
    selector: 'app-ssh-keys',
    standalone: true,
    imports: [CommonModule, FormsModule, ButtonModule, CardModule, DialogModule, InputTextModule, MessageModule, TableModule, TagModule, TextareaModule, TooltipModule],
    template: `
        <div class="mb-4 flex items-start justify-between gap-4">
            <div>
                <h1 class="text-2xl font-semibold m-0">Clés SSH</h1>
                <p class="text-muted-color mt-1 mb-0">Les clés de déploiement servant à cloner les dépôts privés.</p>
            </div>
            <p-button label="Ajouter une clé" icon="pi pi-plus" (onClick)="openForm()" />
        </div>

        <!-- Dit ce qui manque plutôt que d'offrir un bouton qui produirait une paire dont
             on ne peut pas vérifier ici qu'un serveur git l'accepte. -->
        <p-message severity="info" [closable]="false" styleClass="mb-4 w-full">
            La génération d'une paire depuis l'interface n'est pas encore portée. Générez-la avec
            <span class="font-mono">ssh-keygen -t ed25519</span>, puis collez la moitié privée ici.
        </p-message>

        @if (error(); as message) {
            <p-message severity="error" [closable]="false" styleClass="mb-4 w-full">{{ message }}</p-message>
        }

        <p-card>
            <p-table [value]="keys()" [loading]="loading()" dataKey="id" styleClass="p-datatable-sm">
                <ng-template #header>
                    <tr>
                        <th>Nom</th>
                        <th>Clé publique</th>
                        <th>Chiffrement</th>
                        <th>Ajoutée le</th>
                        <th class="text-right">Dépôts</th>
                        <th class="w-1"></th>
                    </tr>
                </ng-template>
                <ng-template #body let-key>
                    <tr>
                        <td class="font-medium">{{ key.name }}</td>
                        <td>
                            @if (key.publicKey) {
                                <span class="font-mono text-sm whitespace-nowrap" [title]="key.publicKey">{{ shorten(key.publicKey) }}</span>
                            } @else {
                                <span class="text-muted-color">—</span>
                            }
                        </td>
                        <td>
                            <p-tag [value]="badge(key.encryptionState).label" [severity]="badge(key.encryptionState).severity"
                                   [pTooltip]="badge(key.encryptionState).hint" tooltipPosition="top" />
                        </td>
                        <td>{{ key.createdAt | date: 'dd/MM/yyyy HH:mm' }}</td>
                        <td class="text-right">{{ key.usedByRepositories }}</td>
                        <td class="text-right">
                            <p-button icon="pi pi-trash" severity="danger" [text]="true" [rounded]="true"
                                      [ariaLabel]="'Supprimer ' + key.name" (onClick)="askDelete(key)" />
                        </td>
                    </tr>
                </ng-template>
                <ng-template #emptymessage>
                    <tr><td colspan="6" class="text-center text-muted-color py-6">Aucune clé enregistrée.</td></tr>
                </ng-template>
            </p-table>
        </p-card>

        <p-dialog header="Ajouter une clé SSH" [(visible)]="formVisible" [modal]="true" [style]="{ width: '40rem' }">
            <div class="flex flex-col gap-4">
                <div class="flex flex-col gap-2">
                    <label for="name" class="font-medium">Nom</label>
                    <input pInputText id="name" [(ngModel)]="form.name" placeholder="Déploiement GitHub" />
                </div>
                <div class="flex flex-col gap-2">
                    <label for="private" class="font-medium">Clé privée</label>
                    <textarea pTextarea id="private" [(ngModel)]="form.privateKey" rows="7" class="font-mono text-sm"
                              placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"></textarea>
                    <small class="text-muted-color">Chiffrée avant écriture, et jamais réaffichée ensuite.</small>
                </div>
                <div class="flex flex-col gap-2">
                    <label for="public" class="font-medium">Clé publique <span class="text-muted-color font-normal">(facultatif)</span></label>
                    <textarea pTextarea id="public" [(ngModel)]="form.publicKey" rows="2" class="font-mono text-sm"
                              placeholder="ssh-ed25519 AAAA…"></textarea>
                    <small class="text-muted-color">Utile pour retrouver quelle clé déclarer chez le fournisseur.</small>
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

        <p-dialog header="Supprimer cette clé ?" [(visible)]="deleteVisible" [modal]="true" [style]="{ width: '30rem' }">
            @if (pendingDelete(); as key) {
                <p class="m-0"><span class="font-medium">{{ key.name }}</span> sera supprimée. C'est définitif.</p>
            }
            <ng-template #footer>
                <p-button label="Annuler" [text]="true" (onClick)="deleteVisible.set(false)" />
                <p-button label="Supprimer" severity="danger" [loading]="saving()" (onClick)="confirmDelete()" />
            </ng-template>
        </p-dialog>
    `
})
export class SshKeys {
    private readonly api = inject(ApiService);

    readonly keys = signal<SshKeySummary[]>([]);
    readonly loading = signal(true);
    readonly saving = signal(false);
    readonly error = signal<string | null>(null);
    readonly formError = signal<string | null>(null);
    readonly formVisible = signal(false);
    readonly deleteVisible = signal(false);
    readonly pendingDelete = signal<SshKeySummary | null>(null);

    form = { name: '', privateKey: '', publicKey: '' };

    constructor() {
        this.reload();
    }

    reload(): void {
        this.loading.set(true);
        this.api.sshKeys().subscribe({
            next: (keys) => {
                this.keys.set(keys);
                this.error.set(null);
                this.loading.set(false);
            },
            error: () => {
                this.error.set('Impossible de charger la liste des clés.');
                this.loading.set(false);
            }
        });
    }

    badge(state: EncryptionState) {
        return ENCRYPTION_LABELS[state] ?? ENCRYPTION_LABELS.unreadable;
    }

    /** Une clé publique tient sur une ligne de 400 caractères : abrégée, comme les
     *  condensés d'images, sous peine d'écraser toutes les autres colonnes. */
    shorten(value: string): string {
        return value.length > 44 ? `${value.slice(0, 44)}…` : value;
    }

    openForm(): void {
        this.form = { name: '', privateKey: '', publicKey: '' };
        this.formError.set(null);
        this.formVisible.set(true);
    }

    submit(): void {
        this.saving.set(true);
        this.api
            .createSshKey({
                name: this.form.name.trim(),
                private_key: this.form.privateKey.trim(),
                public_key: this.form.publicKey.trim() || undefined
            })
            .subscribe({
                next: () => {
                    this.saving.set(false);
                    this.formVisible.set(false);
                    this.reload();
                },
                error: (response) => {
                    this.saving.set(false);
                    // Le serveur sait *pourquoi* — pas une clé privée, aucune clé de
                    // chiffrement configurée. Un message générique perdrait l'action à mener.
                    this.formError.set(response?.error?.message ?? "Impossible d'ajouter cette clé.");
                }
            });
    }

    askDelete(key: SshKeySummary): void {
        this.pendingDelete.set(key);
        this.deleteVisible.set(true);
    }

    confirmDelete(): void {
        const key = this.pendingDelete();
        if (!key) return;
        this.saving.set(true);
        this.api.deleteSshKey(key.id).subscribe({
            next: () => {
                this.saving.set(false);
                this.deleteVisible.set(false);
                this.reload();
            },
            error: (response) => {
                this.saving.set(false);
                this.deleteVisible.set(false);
                // Notamment « utilisée par N dépôts » : le refus porte le nombre à détacher.
                this.error.set(response?.error?.message ?? 'La suppression a échoué.');
            }
        });
    }
}
