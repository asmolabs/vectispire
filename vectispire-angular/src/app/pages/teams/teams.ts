import { CommonModule } from '@angular/common';
import { Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { MultiSelectModule } from '@openng/optimus-ui/multiselect';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import { messageOf } from '../../core/api-error';
import { ApiService } from '../../core/api.service';
import type { TeamSummary, TeamTargetAssignment, UserSummary } from '../../core/api.models';
import { TranslatePipe } from '../../core/i18n/translate.pipe';

/** A target, as the multiselect needs it: one option list across both kinds. */
interface TargetOption {
    label: string;
    value: string;
}

/**
 * Teams: who is in them, and what they own.
 *
 * **Why a team screen beside the per-account one.** Assigning targets account by account is
 * right for an exception and unusable for an organisation — it costs a pairing per account per
 * target, so every arrival means repeating the whole list by hand. This screen edits the
 * factorisation instead, and the account screen keeps the exception.
 *
 * Both halves are sent **wholesale**. A screen that sent only what it added, against a server
 * that only added, would make removing somebody a click that silently does nothing.
 */
@Component({
    selector: 'app-teams',
    standalone: true,
    imports: [
        CommonModule,
        FormsModule,
        ButtonModule,
        CardModule,
        DialogModule,
        InputTextModule,
        MessageModule,
        MultiSelectModule,
        TableModule,
        TagModule,
        TranslatePipe
    ],
    templateUrl: './teams.html'
})
export class Teams {
    private readonly api = inject(ApiService);

    readonly teams = signal<TeamSummary[]>([]);
    readonly accounts = signal<UserSummary[]>([]);
    readonly targetOptions = signal<TargetOption[]>([]);
    readonly loading = signal(true);
    readonly saving = signal(false);
    readonly error = signal<string | null>(null);
    readonly formError = signal<string | null>(null);

    readonly formVisible = signal(false);
    readonly editing = signal<TeamSummary | null>(null);
    readonly accessVisible = signal(false);
    readonly accessTeam = signal<TeamSummary | null>(null);
    readonly deleteVisible = signal(false);
    readonly pendingDelete = signal<TeamSummary | null>(null);
    readonly webhookVisible = signal(false);
    readonly webhookTeam = signal<TeamSummary | null>(null);

    readonly isEmpty = computed(() => this.teams().length === 0);
    /** Options for the member picker: every account, whatever its role. An administrator is
     *  never restricted by visibility, so putting one in a team changes nothing — but excluding
     *  them from the list would make the screen look broken to whoever tried. */
    readonly accountOptions = computed(() =>
        this.accounts().map((account) => ({ label: account.displayName || account.username, value: account.id }))
    );

    form = { name: '', description: '' };
    selectedMembers: number[] = [];
    selectedTargets: string[] = [];
    /** Always starts empty, even for a team that has one: nothing returns the URL, so there is
     *  nothing to prefill. Saving an empty field is how a channel is removed, which is why the
     *  dialog says so rather than leaving it to be discovered. */
    webhookUrl = '';

    constructor() {
        this.reload();
        this.api.users().subscribe({
            // `?? []` and not `result.users`: a payload without the array — a server one version
            // behind, a proxy answering something else — would otherwise throw inside a computed
            // signal, which the `error` handler below cannot catch because nothing errored. The
            // smoke suite answers every request with `[]` precisely to find this.
            next: (result) => this.accounts.set(result?.users ?? []),
            // Silent, and the access dialog says why rather than the page: without the list the
            // membership picker is empty, which is degraded and not broken.
            error: () => this.accounts.set([])
        });
        this.api.apiKeyTargets().subscribe({
            next: (targets) =>
                this.targetOptions.set([
                    ...(targets.repositories ?? []).map((row) => ({
                        label: `Repository — ${row.label}`,
                        value: `repository:${row.id}`
                    })),
                    ...(targets.containers ?? []).map((row) => ({
                        label: `Image — ${row.label}`,
                        value: `container:${row.id}`
                    }))
                ]),
            error: () => this.targetOptions.set([])
        });
    }

    reload(preserveError = false): void {
        this.loading.set(true);
        this.api.teams().subscribe({
            next: (teams) => {
                this.teams.set(teams ?? []);
                if (!preserveError) this.error.set(null);
                this.loading.set(false);
            },
            error: () => {
                this.error.set('Could not load the teams.');
                this.loading.set(false);
            }
        });
    }

    openCreate(): void {
        this.editing.set(null);
        this.form = { name: '', description: '' };
        this.formError.set(null);
        this.formVisible.set(true);
    }

    openRename(team: TeamSummary): void {
        this.editing.set(team);
        this.form = { name: team.name, description: team.description ?? '' };
        this.formError.set(null);
        this.formVisible.set(true);
    }

    save(): void {
        const existing = this.editing();
        const payload = { name: this.form.name, description: this.form.description || null };
        this.saving.set(true);
        this.formError.set(null);

        const request = existing ? this.api.updateTeam(existing.id, payload) : this.api.createTeam(payload);
        request.subscribe({
            next: () => {
                this.saving.set(false);
                this.formVisible.set(false);
                this.reload();
            },
            error: (failure) => {
                this.saving.set(false);
                // Kept on the dialog: the name being taken is the common refusal, and closing
                // the dialog to show it elsewhere loses what was typed.
                this.formError.set(messageOf(failure, 'Could not save the team.'));
            }
        });
    }

    /** Opens the access dialog, reading back what the team currently has. */
    openAccess(team: TeamSummary): void {
        this.accessTeam.set(team);
        this.formError.set(null);
        this.selectedMembers = [];
        this.selectedTargets = [];
        this.accessVisible.set(true);

        this.api.teamMembers(team.id).subscribe({
            next: (ids) => (this.selectedMembers = ids ?? []),
            error: () => this.formError.set('Could not read the current membership.')
        });
        this.api.teamTargets(team.id).subscribe({
            next: (targets) => (this.selectedTargets = (targets ?? []).map((target) => `${target.kind}:${target.id}`)),
            error: () => this.formError.set('Could not read the current targets.')
        });
    }

    saveAccess(): void {
        const team = this.accessTeam();
        if (!team) return;

        const targets: TeamTargetAssignment[] = this.selectedTargets.map((value) => {
            const [kind, id] = value.split(':');
            return { kind, id: Number(id) };
        });

        this.saving.set(true);
        this.formError.set(null);
        this.api.setTeamMembers(team.id, this.selectedMembers).subscribe({
            next: () =>
                this.api.setTeamTargets(team.id, targets).subscribe({
                    next: () => {
                        this.saving.set(false);
                        this.accessVisible.set(false);
                        this.reload();
                    },
                    error: (failure) => {
                        this.saving.set(false);
                        // **The half-state is prepended, not passed as a fallback.** The membership
                        // went through and the targets did not, and `messageOf` prefers the
                        // server's own message — so handing this explanation to it as a fallback
                        // meant that the moment the server said anything at all, the one fact an
                        // administrator needs was dropped. A spec found that; clicking through
                        // never would, because the sentence looks right in isolation.
                        const detail = messageOf(failure, 'Try again.');
                        this.formError.set(`The membership was saved; the targets were not. ${detail}`);
                    }
                }),
            error: (failure) => {
                this.saving.set(false);
                this.formError.set(messageOf(failure, 'Could not save the membership.'));
            }
        });
    }

    openWebhook(team: TeamSummary): void {
        this.webhookTeam.set(team);
        this.webhookUrl = '';
        this.formError.set(null);
        this.webhookVisible.set(true);
    }

    saveWebhook(): void {
        const team = this.webhookTeam();
        if (!team) return;

        this.saving.set(true);
        this.formError.set(null);
        this.api.setTeamWebhook(team.id, this.webhookUrl).subscribe({
            next: () => {
                this.saving.set(false);
                this.webhookVisible.set(false);
                this.reload();
            },
            error: (failure) => {
                this.saving.set(false);
                // The server refuses a private destination unless the deployment allows it, and
                // that message is worth showing verbatim: it names which rule was broken.
                this.formError.set(messageOf(failure, 'Could not save the channel.'));
            }
        });
    }

    confirmDelete(team: TeamSummary): void {
        this.pendingDelete.set(team);
        this.deleteVisible.set(true);
    }

    remove(): void {
        const team = this.pendingDelete();
        if (!team) return;

        this.saving.set(true);
        this.api.deleteTeam(team.id).subscribe({
            next: () => {
                this.saving.set(false);
                this.deleteVisible.set(false);
                this.reload();
            },
            error: (failure) => {
                this.saving.set(false);
                this.deleteVisible.set(false);
                this.error.set(messageOf(failure, 'Could not delete the team.'));
                this.reload(true);
            }
        });
    }
}
