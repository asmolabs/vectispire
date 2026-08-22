import { CommonModule } from '@angular/common';
import { Component, inject, signal } from '@angular/core';
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
import type { AgentSummary, UnroutableLabel } from '../../core/api.models';

const CREDENTIALS = [
    { label: 'Local keys', value: 'local', hint: 'The agent uses its own git credentials. Zanshin sends it no key.' },
    {
        label: 'Delegated keys',
        value: 'delegated',
        hint: 'Zanshin sends the repository deployment key. Requires an encrypted link — the agent is refused otherwise.'
    }
];

import { TranslatePipe } from '../../core/i18n/translate.pipe';

@Component({
    selector: 'app-agents',
    standalone: true,
    imports: [CommonModule, FormsModule, ButtonModule, CardModule, DialogModule, InputNumberModule, InputTextModule, MessageModule, SelectModule, TableModule, TagModule, TranslatePipe],
    templateUrl: './agents.html'
})
export class Agents {
    private readonly api = inject(ApiService);
    readonly credentials = CREDENTIALS;

    readonly agents = signal<AgentSummary[]>([]);
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

    constructor() {
        this.reload();
    }

    hintFor(mode: string): string {
        return CREDENTIALS.find((entry) => entry.value === mode)?.hint ?? '';
    }

    reload(preserveError = false): void {
        this.loading.set(true);
        // **Reloaded together, and the second one failing does not hide the first.** A missing
        // warning is less serious than an empty screen, and the agent list is what the operator
        // came for.
        this.api.unroutableLabels().subscribe({
            next: (blocked) => this.unroutable.set(blocked),
            error: () => this.unroutable.set([])
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

    submit(): void {
        this.saving.set(true);
        this.api
            .createAgent({
                name: this.form.name.trim(),
                description: this.form.description.trim() || undefined,
                credentials_mode: this.form.credentialsMode,
                labels: this.form.labels.trim() || undefined,
                max_concurrent: this.form.maxConcurrent
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
                    this.formError.set(messageOf(response, 'Could not declare this agent.'));
                }
            });
    }

    dismissSecret(): void {
        // Cleared from the model at the same time as from the screen: keeping it would leave
        // accessible dans l'onglet ouvert.
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
        this.saving.set(true);
        this.api.deleteAgent(agent.id).subscribe({
            next: () => {
                this.saving.set(false);
                this.deleteVisible.set(false);
                this.reload();
            },
            error: (response) => {
                this.saving.set(false);
                this.deleteVisible.set(false);
                // Notably "this agent is running N scans": the refusal carries the number.
                this.error.set(messageOf(response, 'The deletion failed.'));
                this.reload(true);
            }
        });
    }
}
