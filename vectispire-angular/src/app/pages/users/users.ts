import { CommonModule } from '@angular/common';
import { I18nService } from '../../core/i18n/i18n.service';
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

import { TranslatePipe } from '../../core/i18n/translate.pipe';

@Component({
    selector: 'app-users',
    standalone: true,
    imports: [CommonModule, FormsModule, ButtonModule, CardModule, DialogModule, InputTextModule, MessageModule, SelectModule, TableModule, TagModule, TranslatePipe],
    templateUrl: './users.html'
})
export class Users {
    private readonly i18n = inject(I18nService);
    private readonly api = inject(ApiService);
    readonly roles = computed(() => {
        this.i18n.translations();
        return [
            { label: this.i18n.t('roles.user'), value: 'USER' },
            { label: this.i18n.t('roles.security_champion'), value: 'SECURITY_CHAMPION' },
            { label: this.i18n.t('roles.ciso'), value: 'CISO' },
            { label: this.i18n.t('roles.admin'), value: 'ADMIN' },
            { label: this.i18n.t('roles.superuser'), value: 'SUPERUSER' }
        ];
    });

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
