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

@Component({
    selector: 'app-agents',
    standalone: true,
    imports: [CommonModule, FormsModule, ButtonModule, CardModule, DialogModule, InputNumberModule, InputTextModule, MessageModule, SelectModule, TableModule, TagModule],
    template: `
        <div class="mb-4 flex items-start justify-between gap-4">
            <div>
                <h1 class="text-2xl font-semibold m-0">Agents</h1>
                <p class="text-muted-color mt-1 mb-0">The remote workers that run the scans.</p>
            </div>
            <p-button label="Declare an agent" icon="pi pi-plus" (onClick)="openForm()" />
        </div>

        @if (error(); as message) {
            <p-message severity="error" [closable]="false" styleClass="mb-4 w-full">{{ message }}</p-message>
        }

        <!--
            **The wait would be silent without this.** A target labelled "customer" while no
            enabled agent carries that label queues its scans, where they stay for ever: the
            Repositories page says "queued", which is true and explains nothing. Here the cause
            is named and the fix is one field away.
        -->
        @for (blocked of unroutable(); track blocked.label) {
            <p-message severity="warn" [closable]="false" styleClass="mb-4 w-full">
                {{ blocked.queued }} scan(s) require the label "{{ blocked.label }}", which no enabled agent carries.
                They will wait until somebody declares it.
            </p-message>
        }

        <p-card>
            <p-table [value]="agents()" [loading]="loading()" dataKey="id" styleClass="p-datatable-sm">
                <ng-template #header>
                    <tr>
                        <th>Agent</th>
                        <th>State</th>
                        <th>Machine</th>
                        <th>Labels</th>
                        <th>Identifiants</th>
                        <th class="text-right">Scans</th>
                        <th class="w-1"></th>
                    </tr>
                </ng-template>
                <ng-template #body let-agent>
                    <tr>
                        <td>
                            <div class="font-medium">{{ agent.name }}</div>
                            @if (agent.description) {
                                <div class="text-sm text-muted-color">{{ agent.description }}</div>
                            }
                        </td>
                        <td>
                            <!--
                                "Online" means seen recently, not enabled. An enabled agent that
                                has been silent for an hour is the case that matters: the queue
                                fills, nobody drains it, and nothing else on the screen would
                                say so.
                            -->
                            @if (!agent.enabled) {
                                <p-tag value="Disabled" severity="secondary" />
                            } @else if (agent.online) {
                                <p-tag value="Online" severity="success" />
                            } @else {
                                <p-tag value="Silent" severity="warn" />
                            }
                            @if (agent.lastSeenAt) {
                                <div class="text-sm text-muted-color mt-1">Seen {{ agent.lastSeenAt | date: 'dd/MM HH:mm' }}</div>
                            } @else {
                                <div class="text-sm text-muted-color mt-1">Never announced</div>
                            }
                        </td>
                        <td>
                            @if (agent.hostname) {
                                <div class="text-sm">{{ agent.hostname }}</div>
                                <div class="text-sm text-muted-color">{{ agent.platform }} · {{ agent.version }}</div>
                            } @else {
                                <span class="text-muted-color">—</span>
                            }
                        </td>
                        <td>
                            @if (agent.labels) {
                                @for (label of agent.labels.split(','); track label) {
                                    <p-tag [value]="label" severity="info" styleClass="mr-1" />
                                }
                            } @else {
                                <!-- With no label, it only takes targets that require none. -->
                                <span class="text-muted-color text-sm">Unlabelled targets</span>
                            }
                        </td>
                        <td>
                            <span class="text-sm">{{ agent.credentialsMode === 'delegated' ? 'Delegated' : 'Local' }}</span>
                            <!--
                                Shown only for delegated credentials: that is the only case where a
                                key leaves. An operator who believes they are sealing while their
                                agent is an older version would have no other way of noticing, and
                                the key would cross their reverse proxy in clear.
                            -->
                            @if (agent.credentialsMode === 'delegated') {
                                <div class="text-sm" [class.text-muted-color]="agent.sealsCredentials">
                                    {{ agent.sealsCredentials ? 'Sealed end to end' : 'In clear under TLS' }}
                                </div>
                            }
                        </td>
                        <td class="text-right">{{ agent.runningScans }}</td>
                        <td class="text-right whitespace-nowrap">
                            <p-button [icon]="agent.enabled ? 'pi pi-ban' : 'pi pi-check'" [text]="true" [rounded]="true"
                                      [ariaLabel]="(agent.enabled ? 'Disable ' : 'Re-enable ') + agent.name"
                                      [disabled]="busy() === agent.id" (onClick)="toggle(agent)" />
                            <p-button icon="pi pi-trash" severity="danger" [text]="true" [rounded]="true"
                                      [ariaLabel]="'Delete ' + agent.name" (onClick)="askDelete(agent)" />
                        </td>
                    </tr>
                </ng-template>
                <ng-template #emptymessage>
                    <tr><td colspan="6" class="text-center text-muted-color py-6">No agent declared. Scans are run by the built-in worker.</td></tr>
                </ng-template>
            </p-table>
        </p-card>

        <p-dialog header="Declare an agent" [(visible)]="formVisible" [modal]="true" [style]="{ width: '34rem' }">
            <div class="flex flex-col gap-4">
                <div class="flex flex-col gap-2">
                    <label for="name" class="font-medium">Name</label>
                    <input pInputText id="name" [(ngModel)]="form.name" placeholder="runner-brussels-1" />
                </div>
                <div class="flex flex-col gap-2">
                    <label for="description" class="font-medium">Description <span class="text-muted-color font-normal">(optional)</span></label>
                    <input pInputText id="description" [(ngModel)]="form.description" />
                </div>
                <div class="flex flex-col gap-2">
                    <label for="mode" class="font-medium">Git credentials</label>
                    <p-select id="mode" [options]="credentials" optionLabel="label" optionValue="value" [(ngModel)]="form.credentialsMode" styleClass="w-full" />
                    <small class="text-muted-color">{{ hintFor(form.credentialsMode) }}</small>
                </div>
                <div class="flex flex-col gap-2">
                    <label for="labels" class="font-medium">Labels</label>
                    <input pInputText id="labels" [(ngModel)]="form.labels" placeholder="production, customer-network" />
                    <small class="text-muted-color">
                        What this agent can reach. A repository or an image may require a label:
                        only the agents carrying it will receive its scans — and its deployment key.
                        With no label, this agent only takes targets that require none.
                    </small>
                </div>
                <div class="flex flex-col gap-2">
                    <label for="concurrent" class="font-medium">Concurrent scans</label>
                    <p-inputnumber inputId="concurrent" [(ngModel)]="form.maxConcurrent" [min]="1" [max]="16" styleClass="w-full" />
                </div>
                @if (formError(); as message) {
                    <p-message severity="error" [closable]="false">{{ message }}</p-message>
                }
            </div>
            <ng-template #footer>
                <p-button label="Cancel" [text]="true" (onClick)="formVisible.set(false)" />
                <p-button label="Declare" [loading]="saving()" (onClick)="submit()" />
            </ng-template>
        </p-dialog>

        <!-- The key exists here only, as for API keys. -->
        <p-dialog header="Agent declared" [(visible)]="secretVisible" [modal]="true" [closable]="false" [style]="{ width: '36rem' }">
            <p-message severity="warn" [closable]="false" styleClass="mb-4 w-full">
                Copy this key now: it is stored only as a hash and cannot be shown again.
                Give it to the agent through the <span class="font-mono">ZANSHIN_API_KEY</span> variable.
            </p-message>
            <div class="font-mono text-sm p-3 border rounded break-all select-all" style="border-color: var(--surface-border)">{{ issuedSecret() }}</div>
            <ng-template #footer>
                <p-button label="I have copied the key" (onClick)="dismissSecret()" />
            </ng-template>
        </p-dialog>

        <p-dialog header="Delete this agent?" [(visible)]="deleteVisible" [modal]="true" [style]="{ width: '30rem' }">
            @if (pendingDelete(); as agent) {
                <p class="m-0">
                    <span class="font-medium">{{ agent.name }}</span> and its API key will be deleted. The agent will no longer be able to claim a scan.
                </p>
            }
            <ng-template #footer>
                <p-button label="Cancel" [text]="true" (onClick)="deleteVisible.set(false)" />
                <p-button label="Delete" severity="danger" [loading]="saving()" (onClick)="confirmDelete()" />
            </ng-template>
        </p-dialog>
    `
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
                this.error.set(response?.error?.message ?? 'The operation failed.');
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
                    this.formError.set(response?.error?.message ?? 'Could not declare this agent.');
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
                this.error.set(response?.error?.message ?? 'The deletion failed.');
                this.reload(true);
            }
        });
    }
}
