import { CommonModule } from '@angular/common';
import { I18nService } from '../../core/i18n/i18n.service';
import { Component, OnDestroy, OnInit, computed, inject, signal } from '@angular/core';
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

@Component({
    selector: 'app-agents',
    standalone: true,
    imports: [CommonModule, FormsModule, ButtonModule, CardModule, DialogModule, InputNumberModule, InputTextModule, MessageModule, SelectModule, TableModule, TagModule, TranslatePipe],
    templateUrl: './agents.html'
})
export class Agents implements OnInit, OnDestroy {
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
    readonly deleteVisible = signal(false);
    readonly pendingDelete = signal<AgentSummary | null>(null);

    form = { name: '', description: '', credentialsMode: 'local', labels: '', maxConcurrent: 1 };

    private timerHandle: any = null;

    ngOnInit(): void {
        this.reload();
        // Auto-refresh activity every 5 seconds to track running scans and pending queues live
        this.timerHandle = setInterval(() => {
            this.refreshActivity();
        }, 5000);
    }

    ngOnDestroy(): void {
        if (this.timerHandle) {
            clearInterval(this.timerHandle);
        }
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
                this.error.set('Could not load the agent list.');
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
                this.error.set(messageOf(response, 'The operation failed.'));
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
            this.formError.set('Name is required.');
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
                this.formError.set(messageOf(response, 'Could not declare the agent.'));
            }
        });
    }

    dismissSecret(): void {
        this.issuedSecret.set(null);
        this.secretVisible.set(false);
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
                this.error.set(messageOf(response, 'Could not delete the agent.'));
            }
        });
    }
}
