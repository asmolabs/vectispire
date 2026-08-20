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
import { messageOf } from '../../core/api-error';
import { ApiService } from '../../core/api.service';
import type { UserSummary } from '../../core/api.models';

const ROLES = [
    { label: 'User', value: 'USER' },
    { label: 'Administrator', value: 'ADMIN' },
    { label: 'Superuser', value: 'SUPERUSER' }
];

@Component({
    selector: 'app-users',
    standalone: true,
    imports: [CommonModule, FormsModule, ButtonModule, CardModule, DialogModule, InputTextModule, MessageModule, SelectModule, TableModule, TagModule],
    template: `
        <div class="mb-4 flex items-start justify-between gap-4">
            <div>
                <h1 class="text-2xl font-semibold m-0">Users</h1>
                <p class="text-muted-color mt-1 mb-0">The accounts allowed to open Zanshin.</p>
            </div>
            <p-button label="Create an account" icon="pi pi-plus" (onClick)="openForm()" />
        </div>

        @if (error(); as message) {
            <p-message severity="error" [closable]="false" styleClass="mb-4 w-full">{{ message }}</p-message>
        }

        <p-card>
            <p-table [value]="users()" [loading]="loading()" dataKey="id" styleClass="p-datatable-sm">
                <ng-template #header>
                    <tr>
                        <th>Username</th>
                        <th>Role</th>
                        <th>State</th>
                        <th class="text-right">Sessions</th>
                        <th>Created</th>
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
                            <!-- Editable in place: it is the most frequent action, and opening a
                                 window to change one value out of three would cost more than it
                                 protects. The server refuses anyway whatever would lock everybody
                                 out. -->
                            <p-select [options]="roles" optionLabel="label" optionValue="value" [ngModel]="user.role"
                                      (ngModelChange)="changeRole(user, $event)" [disabled]="busy() === user.id" styleClass="w-full" />
                        </td>
                        <td>
                            @if (user.isActive) {
                                <p-tag value="Active" severity="success" />
                            } @else {
                                <p-tag value="Disabled" severity="danger" />
                            }
                            @if (user.mustChangePassword) {
                                <div class="text-sm text-muted-color mt-1">Must change its password</div>
                            }
                        </td>
                        <td class="text-right">{{ user.activeSessions }}</td>
                        <td>{{ user.createdAt | date: 'dd/MM/yyyy' }}</td>
                        <td class="text-right whitespace-nowrap">
                            <p-button [icon]="user.isActive ? 'pi pi-ban' : 'pi pi-check'" [text]="true" [rounded]="true"
                                      [ariaLabel]="(user.isActive ? 'Disable ' : 'Re-enable ') + user.username"
                                      [disabled]="busy() === user.id" (onClick)="toggleActive(user)" />
                            <p-button icon="pi pi-key" [text]="true" [rounded]="true"
                                      [ariaLabel]="'Reset the password of ' + user.username"
                                      [disabled]="busy() === user.id" (onClick)="openReset(user)" />
                            <p-button icon="pi pi-trash" severity="danger" [text]="true" [rounded]="true"
                                      [ariaLabel]="'Delete ' + user.username"
                                      [disabled]="busy() === user.id" (onClick)="askDelete(user)" />
                        </td>
                    </tr>
                </ng-template>
                <ng-template #emptymessage>
                    <tr><td colspan="6" class="text-center text-muted-color py-6">No account.</td></tr>
                </ng-template>
            </p-table>
        </p-card>

        <p-dialog header="Create an account" [(visible)]="formVisible" [modal]="true" [style]="{ width: '32rem' }">
            <div class="flex flex-col gap-4">
                <div class="flex flex-col gap-2">
                    <label for="username" class="font-medium">Username</label>
                    <input pInputText id="username" [(ngModel)]="form.username" />
                </div>
                <div class="flex flex-col gap-2">
                    <label for="displayName" class="font-medium">Display name <span class="text-muted-color font-normal">(optional)</span></label>
                    <input pInputText id="displayName" [(ngModel)]="form.displayName" />
                </div>
                <div class="flex flex-col gap-2">
                    <label for="role" class="font-medium">Role</label>
                    <p-select id="role" [options]="roles" optionLabel="label" optionValue="value" [(ngModel)]="form.role" styleClass="w-full" />
                </div>
                <div class="flex flex-col gap-2">
                    <label for="password" class="font-medium">Initial password</label>
                    <input pInputText id="password" [(ngModel)]="form.password" />
                    <small class="text-muted-color">
                        At least 12 characters. Shown because you have to pass it on: it stands in for a
                        one-time pass, and the account will have to change it at first sign-in.
                    </small>
                </div>
                @if (formError(); as message) {
                    <p-message severity="error" [closable]="false">{{ message }}</p-message>
                }
            </div>
            <ng-template #footer>
                <p-button label="Cancel" [text]="true" (onClick)="formVisible.set(false)" />
                <p-button label="Create" [loading]="saving()" (onClick)="submit()" />
            </ng-template>
        </p-dialog>

        <p-dialog header="Reset the password" [(visible)]="resetVisible" [modal]="true" [style]="{ width: '32rem' }">
            @if (pendingReset(); as user) {
                <div class="flex flex-col gap-4">
                    <p class="m-0">New password for <span class="font-medium">{{ user.username }}</span>.</p>
                    <input pInputText [(ngModel)]="resetPassword" />
                    <small class="text-muted-color">The account will have to change it at its next sign-in.</small>
                    @if (formError(); as message) {
                        <p-message severity="error" [closable]="false">{{ message }}</p-message>
                    }
                </div>
            }
            <ng-template #footer>
                <p-button label="Cancel" [text]="true" (onClick)="resetVisible.set(false)" />
                <p-button label="Reset" [loading]="saving()" (onClick)="confirmReset()" />
            </ng-template>
        </p-dialog>

        <p-dialog header="Delete this account?" [(visible)]="deleteVisible" [modal]="true" [style]="{ width: '30rem' }">
            @if (pendingDelete(); as user) {
                <p class="m-0">
                    <span class="font-medium">{{ user.username }}</span> and its sessions will be deleted. This is permanent.
                </p>
            }
            <ng-template #footer>
                <p-button label="Cancel" [text]="true" (onClick)="deleteVisible.set(false)" />
                <p-button label="Delete" severity="danger" [loading]="saving()" (onClick)="confirmDelete()" />
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
    /** The id of the row being modified: two simultaneous actions on the same account would
     *  both start from an already stale state. */
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
     * `preserveError` exists for one precise reason: after a refusal from the server the screen
     * reloads the list to bring it back in line with the database — and used to erase, in the
     * same move, the message that explained the refusal. The button then looked as though it did
     * nothing. It only shows by clicking.
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
                this.error.set('Could not load the account list.');
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
                // own account". Replacing it with a generic message would suggest a fault where
                // there is a rule.
                this.error.set(messageOf(response, 'The operation failed.'));
                // Reloaded to bring the list back in line with the database — otherwise the role
                // selector keeps showing the refused value.
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
                    this.formError.set(messageOf(response, 'Could not create this account.'));
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
                this.formError.set(messageOf(response, 'The reset failed.'));
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
                this.error.set(messageOf(response, 'The deletion failed.'));
                this.reload(true);
            }
        });
    }
}
