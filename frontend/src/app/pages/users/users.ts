import { CommonModule } from '@angular/common';
import { Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { SelectModule } from '@openng/optimus-ui/select';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import { ApiService } from '../../core/api.service';
import type { UserSummary } from '../../core/api.models';

const ROLES = [
    { label: 'Utilisateur', value: 'USER' },
    { label: 'Administrateur', value: 'ADMIN' },
    { label: 'Super-utilisateur', value: 'SUPERUSER' }
];

@Component({
    selector: 'app-users',
    standalone: true,
    imports: [CommonModule, FormsModule, ButtonModule, CardModule, DialogModule, InputTextModule, MessageModule, SelectModule, TableModule, TagModule],
    template: `
        <div class="mb-4 flex items-start justify-between gap-4">
            <div>
                <h1 class="text-2xl font-semibold m-0">Utilisateurs</h1>
                <p class="text-muted-color mt-1 mb-0">Les comptes autorisés à ouvrir Zanshin.</p>
            </div>
            <p-button label="Créer un compte" icon="pi pi-plus" (onClick)="openForm()" />
        </div>

        @if (error(); as message) {
            <p-message severity="error" [closable]="false" styleClass="mb-4 w-full">{{ message }}</p-message>
        }

        <p-card>
            <p-table [value]="users()" [loading]="loading()" dataKey="id" styleClass="p-datatable-sm">
                <ng-template #header>
                    <tr>
                        <th>Identifiant</th>
                        <th>Rôle</th>
                        <th>État</th>
                        <th class="text-right">Sessions</th>
                        <th>Créé le</th>
                        <th class="w-1"></th>
                    </tr>
                </ng-template>
                <ng-template #body let-user>
                    <tr>
                        <td>
                            <div class="font-medium">
                                {{ user.username }}
                                @if (user.id === currentUserId()) {
                                    <span class="text-muted-color font-normal text-sm">(vous)</span>
                                }
                            </div>
                            @if (user.displayName || user.email) {
                                <div class="text-sm text-muted-color">{{ user.displayName || user.email }}</div>
                            }
                        </td>
                        <td>
                            <!-- Modifiable en place : c'est l'action la plus fréquente, et
                                 ouvrir une fenêtre pour changer une valeur parmi trois
                                 coûterait plus qu'elle ne protège. Le serveur refuse de
                                 toute façon ce qui verrouillerait tout le monde dehors. -->
                            <p-select [options]="roles" optionLabel="label" optionValue="value" [ngModel]="user.role"
                                      (ngModelChange)="changeRole(user, $event)" [disabled]="busy() === user.id" styleClass="w-full" />
                        </td>
                        <td>
                            @if (user.isActive) {
                                <p-tag value="Actif" severity="success" />
                            } @else {
                                <p-tag value="Désactivé" severity="danger" />
                            }
                            @if (user.mustChangePassword) {
                                <div class="text-sm text-muted-color mt-1">Doit changer son mot de passe</div>
                            }
                        </td>
                        <td class="text-right">{{ user.activeSessions }}</td>
                        <td>{{ user.createdAt | date: 'dd/MM/yyyy' }}</td>
                        <td class="text-right whitespace-nowrap">
                            <p-button [icon]="user.isActive ? 'pi pi-ban' : 'pi pi-check'" [text]="true" [rounded]="true"
                                      [ariaLabel]="(user.isActive ? 'Désactiver ' : 'Réactiver ') + user.username"
                                      [disabled]="busy() === user.id" (onClick)="toggleActive(user)" />
                            <p-button icon="pi pi-key" [text]="true" [rounded]="true"
                                      [ariaLabel]="'Réinitialiser le mot de passe de ' + user.username"
                                      [disabled]="busy() === user.id" (onClick)="openReset(user)" />
                            <p-button icon="pi pi-trash" severity="danger" [text]="true" [rounded]="true"
                                      [ariaLabel]="'Supprimer ' + user.username"
                                      [disabled]="busy() === user.id" (onClick)="askDelete(user)" />
                        </td>
                    </tr>
                </ng-template>
                <ng-template #emptymessage>
                    <tr><td colspan="6" class="text-center text-muted-color py-6">Aucun compte.</td></tr>
                </ng-template>
            </p-table>
        </p-card>

        <p-dialog header="Créer un compte" [(visible)]="formVisible" [modal]="true" [style]="{ width: '32rem' }">
            <div class="flex flex-col gap-4">
                <div class="flex flex-col gap-2">
                    <label for="username" class="font-medium">Identifiant</label>
                    <input pInputText id="username" [(ngModel)]="form.username" />
                </div>
                <div class="flex flex-col gap-2">
                    <label for="displayName" class="font-medium">Nom affiché <span class="text-muted-color font-normal">(facultatif)</span></label>
                    <input pInputText id="displayName" [(ngModel)]="form.displayName" />
                </div>
                <div class="flex flex-col gap-2">
                    <label for="role" class="font-medium">Rôle</label>
                    <p-select id="role" [options]="roles" optionLabel="label" optionValue="value" [(ngModel)]="form.role" styleClass="w-full" />
                </div>
                <div class="flex flex-col gap-2">
                    <label for="password" class="font-medium">Mot de passe initial</label>
                    <input pInputText id="password" [(ngModel)]="form.password" />
                    <small class="text-muted-color">
                        Au moins 12 caractères. Visible parce que vous devez le transmettre : il tient lieu de
                        laissez-passer, et le compte devra le changer à sa première connexion.
                    </small>
                </div>
                @if (formError(); as message) {
                    <p-message severity="error" [closable]="false">{{ message }}</p-message>
                }
            </div>
            <ng-template #footer>
                <p-button label="Annuler" [text]="true" (onClick)="formVisible.set(false)" />
                <p-button label="Créer" [loading]="saving()" (onClick)="submit()" />
            </ng-template>
        </p-dialog>

        <p-dialog header="Réinitialiser le mot de passe" [(visible)]="resetVisible" [modal]="true" [style]="{ width: '32rem' }">
            @if (pendingReset(); as user) {
                <div class="flex flex-col gap-4">
                    <p class="m-0">Nouveau mot de passe pour <span class="font-medium">{{ user.username }}</span>.</p>
                    <input pInputText [(ngModel)]="resetPassword" />
                    <small class="text-muted-color">Le compte devra le changer à sa prochaine connexion.</small>
                    @if (formError(); as message) {
                        <p-message severity="error" [closable]="false">{{ message }}</p-message>
                    }
                </div>
            }
            <ng-template #footer>
                <p-button label="Annuler" [text]="true" (onClick)="resetVisible.set(false)" />
                <p-button label="Réinitialiser" [loading]="saving()" (onClick)="confirmReset()" />
            </ng-template>
        </p-dialog>

        <p-dialog header="Supprimer ce compte ?" [(visible)]="deleteVisible" [modal]="true" [style]="{ width: '30rem' }">
            @if (pendingDelete(); as user) {
                <p class="m-0">
                    <span class="font-medium">{{ user.username }}</span> et ses sessions seront supprimés. C'est définitif.
                </p>
            }
            <ng-template #footer>
                <p-button label="Annuler" [text]="true" (onClick)="deleteVisible.set(false)" />
                <p-button label="Supprimer" severity="danger" [loading]="saving()" (onClick)="confirmDelete()" />
            </ng-template>
        </p-dialog>
    `
})
export class Users {
    private readonly api = inject(ApiService);
    readonly roles = ROLES;

    readonly users = signal<UserSummary[]>([]);
    readonly currentUserId = signal<number | null>(null);
    readonly loading = signal(true);
    readonly saving = signal(false);
    /** L'identifiant de la ligne en cours de modification : deux actions simultanées sur
     *  le même compte partiraient d'un état déjà périmé. */
    readonly busy = signal<number | null>(null);
    readonly error = signal<string | null>(null);
    readonly formError = signal<string | null>(null);
    readonly formVisible = signal(false);
    readonly resetVisible = signal(false);
    readonly deleteVisible = signal(false);
    readonly pendingReset = signal<UserSummary | null>(null);
    readonly pendingDelete = signal<UserSummary | null>(null);
    readonly isEmpty = computed(() => this.users().length === 0);

    form = { username: '', displayName: '', role: 'USER', password: '' };
    resetPassword = '';

    constructor() {
        this.reload();
    }

    /**
     * `preserveError` existe pour une raison précise : après un refus du serveur, l'écran
     * recharge la liste pour la remettre en accord avec la base — et effaçait du même coup
     * le message qui expliquait le refus. Le bouton semblait alors ne rien faire. Ça ne se
     * voit qu'en cliquant.
     */
    reload(preserveError = false): void {
        this.loading.set(true);
        this.api.users().subscribe({
            next: (result) => {
                this.users.set(result.users);
                this.currentUserId.set(result.currentUserId);
                if (!preserveError) this.error.set(null);
                this.loading.set(false);
            },
            error: () => {
                this.error.set('Impossible de charger la liste des comptes.');
                this.loading.set(false);
            }
        });
    }

    changeRole(user: UserSummary, role: string): void {
        if (role === user.role) return;
        this.patch(user, { role });
    }

    toggleActive(user: UserSummary): void {
        this.patch(user, { is_active: !user.isActive });
    }

    private patch(user: UserSummary, body: { role?: string; is_active?: boolean; password?: string }): void {
        this.busy.set(user.id);
        this.error.set(null);
        this.api.updateUser(user.id, body).subscribe({
            next: () => {
                this.busy.set(null);
                this.reload();
            },
            error: (response) => {
                this.busy.set(null);
                // Le refus porte sa raison — « dernier administrateur actif », « votre
                // propre compte ». La remplacer par un message générique laisserait
                // croire à une panne là où il y a une règle.
                this.error.set(response?.error?.message ?? "L'opération a échoué.");
                // Rechargement pour remettre la liste en accord avec la base — le sélecteur
                // de rôle affiche sinon la valeur refusée.
                this.reload(true);
            }
        });
    }

    openForm(): void {
        this.form = { username: '', displayName: '', role: 'USER', password: '' };
        this.formError.set(null);
        this.formVisible.set(true);
    }

    submit(): void {
        this.saving.set(true);
        this.api
            .createUser({
                username: this.form.username.trim(),
                password: this.form.password,
                role: this.form.role,
                display_name: this.form.displayName.trim() || undefined
            })
            .subscribe({
                next: () => {
                    this.saving.set(false);
                    this.formVisible.set(false);
                    this.reload();
                },
                error: (response) => {
                    this.saving.set(false);
                    this.formError.set(response?.error?.message ?? 'Impossible de créer ce compte.');
                }
            });
    }

    openReset(user: UserSummary): void {
        this.pendingReset.set(user);
        this.resetPassword = '';
        this.formError.set(null);
        this.resetVisible.set(true);
    }

    confirmReset(): void {
        const user = this.pendingReset();
        if (!user) return;
        this.saving.set(true);
        this.api.updateUser(user.id, { password: this.resetPassword }).subscribe({
            next: () => {
                this.saving.set(false);
                this.resetVisible.set(false);
                this.reload();
            },
            error: (response) => {
                this.saving.set(false);
                this.formError.set(response?.error?.message ?? 'La réinitialisation a échoué.');
            }
        });
    }

    askDelete(user: UserSummary): void {
        this.pendingDelete.set(user);
        this.deleteVisible.set(true);
    }

    confirmDelete(): void {
        const user = this.pendingDelete();
        if (!user) return;
        this.saving.set(true);
        this.api.deleteUser(user.id).subscribe({
            next: () => {
                this.saving.set(false);
                this.deleteVisible.set(false);
                this.reload();
            },
            error: (response) => {
                this.saving.set(false);
                this.deleteVisible.set(false);
                this.error.set(response?.error?.message ?? 'La suppression a échoué.');
                this.reload(true);
            }
        });
    }
}
