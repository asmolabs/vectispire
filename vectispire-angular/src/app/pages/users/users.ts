import { CommonModule } from '@angular/common';
import { I18nService } from '../../core/i18n/i18n.service';
import { Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { MultiSelectModule } from '@openng/optimus-ui/multiselect';
import { SelectModule } from '@openng/optimus-ui/select';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import { messageOf } from '../../core/api-error';
import { AccountsApi } from '../../core/api/accounts.api';
import { SettingsApi } from '../../core/api/settings.api';
import type { ApiKeyTargets, UserSummary, UserTargetAssignment } from '../../core/api.models';
import { GOVERNANCE_READER_ROLES } from '../../core/session.store';

import { TranslatePipe } from '../../core/i18n/translate.pipe';

/** A list from the server, or none: read inside a computed the template renders, anything else would break the screen. */
const listOf = <T>(rows: T[] | null | undefined): T[] => (Array.isArray(rows) ? rows : []);

@Component({
    selector: 'app-users',
    standalone: true,
    imports: [CommonModule, FormsModule, ButtonModule, CardModule, DialogModule, InputTextModule, MessageModule, MultiSelectModule, SelectModule, TableModule, TagModule, TranslatePipe],
    templateUrl: './users.html'
})
export class Users {
    private readonly i18n = inject(I18nService);
    private readonly accountsApi = inject(AccountsApi);
    private readonly settingsApi = inject(SettingsApi);
    readonly roles = computed(() => {
        this.i18n.translations();
        return [
            { label: this.i18n.t('roles.user'), value: 'USER' },
            // Between USER and the roles that act: sees the whole estate, changes none of it.
            { label: this.i18n.t('roles.auditor'), value: 'AUDITOR' },
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

    /**
     * Visibility, account by account.
     *
     * <p><b>This half of the model could only be administered through the API.</b>
     * {@code VisibilityService} reads the direct assignments to decide what an account sees — it is
     * the read scope of the entire application — and teams had their screen when accounts had none.
     * Restricting somebody took a `curl`, which amounts to not offering the restriction at all.
     */
    readonly accessVisible = signal(false);
    readonly accessUser = signal<UserSummary | null>(null);
    private readonly targets = signal<ApiKeyTargets | null>(null);

    /** Labelled at render time, not at load: the language changes at runtime. */
    readonly targetOptions = computed<{ label: string; value: string }[]>(() => {
        this.i18n.translations();
        const targets = this.targets();
        return [
            ...listOf(targets?.repositories).map((row) => ({
                label: `${this.i18n.t('users.target_repository')} — ${row.label}`,
                value: `repository:${row.id}`
            })),
            ...listOf(targets?.containers).map((row) => ({
                label: `${this.i18n.t('users.target_image')} — ${row.label}`,
                value: `container:${row.id}`
            }))
        ];
    });
    selectedTargets: string[] = [];

    /**
     * The deployment's visibility mode, read so the screen can denounce itself.
     *
     * <p>In {@code everyone} mode, every signed-in account sees the whole estate and these
     * assignments decide nothing. A screen letting somebody tick targets without saying so would
     * suggest a restriction had been applied; the same fault as the work order that did not explain
     * its single line.
     */
    readonly visibilityMode = signal<string | null>(null);

    /** Vrai quand le mode rend ces affectations sans effet, pour personne. */
    readonly restrictionsInactive = computed(() => this.visibilityMode() === 'everyone');

    /**
     * The open account's role ignores every restriction.
     *
     * <p>The globally scoped roles are exactly those that read governance — deliberately so on the
     * server: reading the audit log or the gate policy tells you about every target's posture, so
     * granting it to a restricted account would bypass the scope rather than be a reduced version
     * of it.
     */
    readonly accessUnrestricted = computed(() => {
        const role = this.accessUser()?.role;
        return role != null && GOVERNANCE_READER_ROLES.includes(role);
    });

    constructor() {
        this.reload();

        // The targets and the mode are loaded separately: failing to get them degrades the dialog
        // without preventing the administration of accounts, which is the screen's subject.
        this.accountsApi.apiKeyTargets().subscribe({
            next: (targets) => this.targets.set(targets ?? null),
            error: () => this.targets.set(null)
        });
        this.settingsApi.settings().subscribe({
            next: (result) => this.visibilityMode.set(
                (result?.settings ?? []).find((setting) => setting.key === 'target_visibility')?.value ?? null),
            error: () => this.visibilityMode.set(null)
        });
    }

    /** Opens the visibility dialog, reading again what the account has today. */
    openAccess(user: UserSummary): void {
        this.accessUser.set(user);
        this.formError.set(null);
        this.selectedTargets = [];
        this.accessVisible.set(true);

        this.accountsApi.userTargets(user.id).subscribe({
            next: (targets) =>
                (this.selectedTargets = (targets ?? []).map((target) => `${target.kind}:${target.id}`)),
            error: () => this.formError.set(this.i18n.t('users.access_read_failed'))
        });
    }

    /**
     * Sends the set as it is shown, empty included.
     *
     * <p>Empty is a decision and not the absence of one: it is how one takes away everything
     * somebody could see, and a guard of "send nothing if nothing is ticked" would have made that
     * removal a button with no effect.
     */
    saveAccess(): void {
        const user = this.accessUser();
        if (!user) return;

        const targets: UserTargetAssignment[] = this.selectedTargets.map((value) => {
            const [kind, id] = value.split(':');
            return { kind, id: Number(id) };
        });

        this.saving.set(true);
        this.formError.set(null);
        this.accountsApi.setUserTargets(user.id, targets).subscribe({
            next: () => {
                this.saving.set(false);
                this.accessVisible.set(false);
            },
            error: (response) => {
                this.saving.set(false);
                this.formError.set(messageOf(response, this.i18n.t('users.access_save_failed')));
            }
        });
    }

    /**
     * `preserveError` exists for one precise reason: after a refusal from the server the screen
     * reloads the list to bring it back in line with the database — and used to erase, in the
     * same move, the message that explained the refusal. The button then looked as though it did
     * nothing. It only shows by clicking.
     */
    reload(preserveError = false): void {
        this.loading.set(true);
        this.accountsApi.users().subscribe({
            next: (result) => {
                this.users.set(result.users);
                this.currentUserId.set(result.currentUserId);
                if (!preserveError) this.error.set(null);
                this.loading.set(false);
            },
            error: () => {
                this.error.set(this.i18n.t('users.error_load'));
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
        this.accountsApi.updateUser(user.id, body).subscribe({
            next: () => {
                this.busy.set(null);
                this.reload();
            },
            error: (response) => {
                this.busy.set(null);
                // Le refus porte sa raison — « dernier administrateur actif », « votre
                // own account". Replacing it with a generic message would suggest a fault where
                // there is a rule.
                this.error.set(messageOf(response, this.i18n.t('users.error_operation')));
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
        this.accountsApi
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
                    this.formError.set(messageOf(response, this.i18n.t('users.error_create')));
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
        this.accountsApi.updateUser(user.id, { password: this.resetPassword }).subscribe({
            next: () => {
                this.saving.set(false);
                this.resetVisible.set(false);
                this.reload();
            },
            error: (response) => {
                this.saving.set(false);
                this.formError.set(messageOf(response, this.i18n.t('users.error_reset')));
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
        this.accountsApi.deleteUser(user.id).subscribe({
            next: () => {
                this.saving.set(false);
                this.deleteVisible.set(false);
                this.reload();
            },
            error: (response) => {
                this.saving.set(false);
                this.deleteVisible.set(false);
                this.error.set(messageOf(response, this.i18n.t('users.error_delete')));
                this.reload(true);
            }
        });
    }
}
