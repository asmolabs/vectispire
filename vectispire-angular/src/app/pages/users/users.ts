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
import { ApiService } from '../../core/api.service';
import type { UserSummary, UserTargetAssignment } from '../../core/api.models';
import { GOVERNANCE_READER_ROLES } from '../../core/session.store';

import { TranslatePipe } from '../../core/i18n/translate.pipe';

@Component({
    selector: 'app-users',
    standalone: true,
    imports: [CommonModule, FormsModule, ButtonModule, CardModule, DialogModule, InputTextModule, MessageModule, MultiSelectModule, SelectModule, TableModule, TagModule, TranslatePipe],
    templateUrl: './users.html'
})
export class Users {
    private readonly i18n = inject(I18nService);
    private readonly api = inject(ApiService);
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
     * La visibilité, compte par compte.
     *
     * <p><b>Cette moitié du modèle n'était administrable que par l'API.</b>
     * {@code VisibilityService} lit les affectations directes pour décider de ce qu'un compte
     * voit — c'est le champ de lecture de l'application entière — et les équipes avaient leur
     * écran quand les comptes n'en avaient pas. Restreindre quelqu'un demandait un `curl`, ce qui
     * revient à ne pas offrir la restriction du tout.
     */
    readonly accessVisible = signal(false);
    readonly accessUser = signal<UserSummary | null>(null);
    readonly targetOptions = signal<{ label: string; value: string }[]>([]);
    selectedTargets: string[] = [];

    /**
     * Le mode de visibilité du déploiement, lu pour pouvoir se dénoncer.
     *
     * <p>En mode {@code everyone}, tout compte connecté voit tout le parc et ces affectations ne
     * décident de rien. Un écran qui laisserait cocher des cibles sans le dire ferait croire à
     * une restriction posée ; c'est la même faute que l'ordre de travail qui n'expliquait pas son
     * unique ligne.
     */
    readonly visibilityMode = signal<string | null>(null);

    /** Vrai quand le mode rend ces affectations sans effet, pour personne. */
    readonly restrictionsInactive = computed(() => this.visibilityMode() === 'everyone');

    /**
     * Le rôle du compte ouvert ignore toute restriction.
     *
     * <p>Les rôles à portée globale sont exactement ceux qui lisent la gouvernance — c'est
     * délibéré côté serveur : lire le journal d'audit ou la politique de barrière renseigne sur
     * la posture de toutes les cibles, donc l'accorder à un compte restreint contournerait la
     * portée au lieu d'en être une version réduite.
     */
    readonly accessUnrestricted = computed(() => {
        const role = this.accessUser()?.role;
        return role != null && GOVERNANCE_READER_ROLES.includes(role);
    });

    constructor() {
        this.reload();

        // Les cibles et le mode sont chargés à part : ne pas les obtenir dégrade la boîte de
        // dialogue sans empêcher d'administrer les comptes, qui est le sujet de l'écran.
        this.api.apiKeyTargets().subscribe({
            next: (targets) =>
                this.targetOptions.set([
                    ...(targets?.repositories ?? []).map((row) => ({
                        label: `${this.i18n.t('users.target_repository')} — ${row.label}`,
                        value: `repository:${row.id}`
                    })),
                    ...(targets?.containers ?? []).map((row) => ({
                        label: `${this.i18n.t('users.target_image')} — ${row.label}`,
                        value: `container:${row.id}`
                    }))
                ]),
            error: () => this.targetOptions.set([])
        });
        this.api.settings().subscribe({
            next: (result) => this.visibilityMode.set(
                (result?.settings ?? []).find((setting) => setting.key === 'target_visibility')?.value ?? null),
            error: () => this.visibilityMode.set(null)
        });
    }

    /** Ouvre la boîte de visibilité, en relisant ce que le compte a aujourd'hui. */
    openAccess(user: UserSummary): void {
        this.accessUser.set(user);
        this.formError.set(null);
        this.selectedTargets = [];
        this.accessVisible.set(true);

        this.api.userTargets(user.id).subscribe({
            next: (targets) =>
                (this.selectedTargets = (targets ?? []).map((target) => `${target.kind}:${target.id}`)),
            error: () => this.formError.set(this.i18n.t('users.access_read_failed'))
        });
    }

    /**
     * Envoie l'ensemble tel qu'il est affiché, vide compris.
     *
     * <p>Le vide est une décision et non une absence de décision : c'est ainsi qu'on retire à
     * quelqu'un tout ce qu'il voyait, et une garde « ne rien envoyer si rien n'est coché » aurait
     * fait de ce retrait un bouton sans effet.
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
        this.api.setUserTargets(user.id, targets).subscribe({
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
