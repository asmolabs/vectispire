import { CommonModule } from '@angular/common';
import { I18nService } from '../../core/i18n/i18n.service';
import { Component, OnInit, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { InputNumberModule } from '@openng/optimus-ui/inputnumber';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { SelectModule } from '@openng/optimus-ui/select';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import { messageOf } from '../../core/api-error';
import { ApiService } from '../../core/api.service';
import type { AgentActivitySummary, AgentSummary, RunningScanItem, UnroutableLabel } from '../../core/api.models';


import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { pollWhile } from '@/app/core/poll-while';

@Component({
    selector: 'app-agents',
    standalone: true,
    imports: [CommonModule, FormsModule, ButtonModule, CardModule, DialogModule, InputNumberModule, InputTextModule, MessageModule, SelectModule, TableModule, TagModule, TranslatePipe],
    templateUrl: './agents.html'
})
export class Agents implements OnInit {
    private readonly i18n = inject(I18nService);
    private readonly api = inject(ApiService);
    readonly credentials = computed(() => {
        this.i18n.translations();
        return [
            { label: this.i18n.t('agents.credentials_modes.local'), value: 'local', hint: this.i18n.t('agents.credentials_modes.local_hint') },
            { label: this.i18n.t('agents.credentials_modes.delegated'), value: 'delegated', hint: this.i18n.t('agents.credentials_modes.delegated_hint') }
        ];
    });

    readonly agents = signal<AgentSummary[]>([]);
    readonly activity = signal<AgentActivitySummary | null>(null);
    readonly unroutable = signal<UnroutableLabel[]>([]);
    readonly loading = signal(true);
    readonly saving = signal(false);
    readonly busy = signal<string | null>(null);
    readonly error = signal<string | null>(null);
    readonly formError = signal<string | null>(null);
    readonly formVisible = signal(false);
    readonly secretVisible = signal(false);
    readonly issuedSecret = signal<string | null>(null);

    /**
     * The private half of a freshly pinned signing key, shown once.
     *
     * Same dialog shape as the API key for the same reason: the control plane does not keep it,
     * so this is the operator's only chance to put it in the agent's configuration.
     */
    readonly signingKeyVisible = signal(false);
    readonly issuedSigningKey = signal<string | null>(null);
    readonly deleteVisible = signal(false);
    readonly pendingDelete = signal<AgentSummary | null>(null);

    form = { name: '', description: '', credentialsMode: 'local', labels: '', maxConcurrent: 1 };

    /**
     * **Only counts while there is something to wait for.**
     *
     * This screen queried the server every five seconds unconditionally — 720 requests an hour per
     * open tab, including on an estate where nothing is running. The first load says whether there
     * is activity; the timer starts only if there is, and stops as soon as the queue is empty.
     */
    private readonly hasActivity = computed(() => {
        const activity = this.activity();
        return (activity?.runningScans?.length ?? 0) > 0 || (activity?.pendingScans?.length ?? 0) > 0;
    });

    constructor() {
        pollWhile(this.hasActivity, () => this.refreshActivity());
    }

    ngOnInit(): void {
        this.reload();
        this.refreshActivity();
    }

    hintFor(mode: string): string {
        return this.credentials().find((entry) => entry.value === mode)?.hint ?? '';
    }

    formatDuration(seconds: number): string {
        if (!seconds || seconds <= 0) return '0s';
        const m = Math.floor(seconds / 60);
        const s = seconds % 60;
        if (m > 0) {
            return `${m}m ${s}s`;
        }
        return `${s}s`;
    }

    getRunningScanForAgent(agentId: string): RunningScanItem | undefined {
        return this.activity()?.runningScans.find((s) => s.agentId === agentId);
    }

    refreshActivity(): void {
        this.api.getAgentActivity().subscribe({
            next: (act) => this.activity.set(act),
            error: () => {}
        });
    }

    reload(preserveError = false): void {
        this.loading.set(true);

        this.api.unroutableLabels().subscribe({
            next: (blocked) => this.unroutable.set(blocked),
            error: () => this.unroutable.set([])
        });

        this.api.getAgentActivity().subscribe({
            next: (act) => this.activity.set(act),
            error: () => {}
        });

        this.api.agents().subscribe({
            next: (agents) => {
                this.agents.set(agents);
                if (!preserveError) this.error.set(null);
                this.loading.set(false);
            },
            error: () => {
                this.error.set(this.i18n.t('agents.error_load'));
                this.loading.set(false);
            }
        });
    }

    toggle(agent: AgentSummary): void {
        this.busy.set(agent.id);
        this.error.set(null);
        this.api.setAgentEnabled(agent.id, !agent.enabled).subscribe({
            next: () => {
                this.busy.set(null);
                this.reload();
            },
            error: (response) => {
                this.busy.set(null);
                this.error.set(messageOf(response, this.i18n.t('agents.error_operation')));
                this.reload(true);
            }
        });
    }

    openForm(): void {
        this.form = { name: '', description: '', credentialsMode: 'local', labels: '', maxConcurrent: 1 };
        this.formError.set(null);
        this.formVisible.set(true);
    }

    save(): void {
        if (!this.form.name.trim()) {
            this.formError.set(this.i18n.t('agents.error_name_required'));
            return;
        }
        this.saving.set(true);
        this.formError.set(null);
        this.api.createAgent({
            name: this.form.name.trim(),
            description: this.form.description.trim() || undefined,
            credentials_mode: this.form.credentialsMode,
            labels: this.form.labels.trim() || undefined,
            max_concurrent: this.form.maxConcurrent
        }).subscribe({
            next: ({ secret }) => {
                this.saving.set(false);
                this.formVisible.set(false);
                this.issuedSecret.set(secret);
                this.secretVisible.set(true);
                this.reload();
            },
            error: (response) => {
                this.saving.set(false);
                this.formError.set(messageOf(response, this.i18n.t('agents.error_declare')));
            }
        });
    }

    dismissSecret(): void {
        this.issuedSecret.set(null);
        this.secretVisible.set(false);
    }

    /**
     * Pins a generated key, or removes the one that is there.
     *
     * Removing is a confirmation-free single click on purpose here — it is audited, and the row
     * immediately says the agent is no longer attested, which is the feedback that matters.
     */
    toggleSigning(agent: AgentSummary): void {
        this.busy.set(agent.id);
        this.api.pinAgentSigningKey(agent.id, agent.signsResults ? '' : 'generate').subscribe({
            next: (pinned) => {
                this.busy.set(null);
                if (pinned.privateKey) {
                    this.issuedSigningKey.set(pinned.privateKey);
                    this.signingKeyVisible.set(true);
                }
                this.reload();
            },
            error: (response) => {
                this.busy.set(null);
                this.error.set(messageOf(response, this.i18n.t('agents.error_signing_key')));
            }
        });
    }

    dismissSigningKey(): void {
        this.issuedSigningKey.set(null);
        this.signingKeyVisible.set(false);
    }

    askDelete(agent: AgentSummary): void {
        this.pendingDelete.set(agent);
        this.deleteVisible.set(true);
    }

    confirmDelete(): void {
        const agent = this.pendingDelete();
        if (!agent) return;
        this.api.deleteAgent(agent.id).subscribe({
            next: () => {
                this.deleteVisible.set(false);
                this.pendingDelete.set(null);
                this.reload();
            },
            error: (response) => {
                this.deleteVisible.set(false);
                this.pendingDelete.set(null);
                this.error.set(messageOf(response, this.i18n.t('agents.error_delete')));
            }
        });
    }
}
