import { CommonModule } from '@angular/common';
import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { TableModule } from '@openng/optimus-ui/table';
import { messageOf } from '../../core/api-error';
import { ApiService } from '../../core/api.service';
import type { MonitoredRepository } from '../../core/api.models';
import { SessionStore } from '../../core/session.store';
import { LastScanTag } from '../../shared/last-scan';

@Component({
    selector: 'app-repositories',
    standalone: true,
    imports: [CommonModule, FormsModule, RouterLink, ButtonModule, CardModule, DialogModule, InputTextModule, MessageModule, TableModule, LastScanTag],
    template: `
        <div class="mb-4 flex items-start justify-between gap-4">
            <div>
                <h1 class="text-2xl font-semibold m-0">Repositories</h1>
                <p class="text-muted-color mt-1 mb-0">The monitored git repositories and the state of their last scan.</p>
            </div>
            @if (isAdmin()) {
                <p-button label="Add a repository" icon="pi pi-plus" (onClick)="openForm()" />
            }
        </div>

        @if (error(); as message) {
            <p-message severity="error" [closable]="false" styleClass="mb-4 w-full">{{ message }}</p-message>
        }
        @if (notice(); as message) {
            <p-message severity="success" [closable]="false" styleClass="mb-4 w-full">{{ message }}</p-message>
        }

        <p-card>
            <p-table [value]="repositories()" [loading]="loading()" dataKey="id" styleClass="p-datatable-sm">
                <ng-template #header>
                    <tr>
                        <th>Repository</th>
                        <th>Branch</th>
                        <th>Last scan</th>
                        <th class="text-right">Outstanding</th>
                        @if (isAdmin()) { <th class="w-1"></th> }
                    </tr>
                </ng-template>
                <ng-template #body let-repository>
                    <tr>
                        <td>
                            <div class="font-medium">{{ repository.displayName }}</div>
                            <div class="text-sm text-muted-color break-all">
                                {{ repository.url }}
                                <!--
                                    Shown because two rows can now be the same URL. Without it a
                                    monorepo registered twice reads as the same target listed
                                    twice, and nobody can tell which one they are scanning.
                                -->
                                @if (repository.subPath) {
                                    <span class="font-mono">· {{ repository.subPath }}</span>
                                }
                            </div>
                        </td>
                        <td>{{ repository.branch }}</td>
                        <td>
                            @if (repository.lastScan; as scan) {
                                <a [routerLink]="['/scans', scan.id]"><app-last-scan [scan]="scan" /></a>
                            } @else {
                                <app-last-scan [scan]="null" />
                            }
                        </td>
                        <td class="text-right">
                            @if (repository.openIssues > 0) {
                                <a [routerLink]="['/issues']" [queryParams]="{ repository_id: repository.id }" class="font-medium">{{ repository.openIssues }}</a>
                            } @else {
                                <span class="text-muted-color">0</span>
                            }
                        </td>
                        @if (isAdmin()) {
                            <td class="text-right whitespace-nowrap">
                                <p-button icon="pi pi-play" [text]="true" [rounded]="true"
                                          [ariaLabel]="'Run a scan of ' + repository.url"
                                          [disabled]="busy() === repository.id" (onClick)="triggerScan(repository)" />
                                <p-button icon="pi pi-pencil" [text]="true" [rounded]="true"
                                          [ariaLabel]="'Edit ' + repository.url" (onClick)="openForm(repository)" />
                                <p-button icon="pi pi-trash" severity="danger" [text]="true" [rounded]="true"
                                          [ariaLabel]="'Delete ' + repository.url" (onClick)="askDelete(repository)" />
                            </td>
                        }
                    </tr>
                </ng-template>
                <ng-template #emptymessage>
                    <tr><td [attr.colspan]="isAdmin() ? 5 : 4" class="text-center text-muted-color py-6">No monitored repository.</td></tr>
                </ng-template>
            </p-table>
        </p-card>

        <p-dialog [header]="editing() ? 'Edit this repository' : 'Add a repository'" [(visible)]="formVisible" [modal]="true" [style]="{ width: '32rem' }">
            <div class="flex flex-col gap-4">
                <div class="flex flex-col gap-2">
                    <label for="url" class="font-medium">Repository URL</label>
                    <input pInputText id="url" [(ngModel)]="form.url" placeholder="https://github.com/org/projet.git" />
                    <small class="text-muted-color">https://…, ssh://… or git&#64;host:path</small>
                </div>
                <div class="flex flex-col gap-2">
                    <label for="branch" class="font-medium">Branch</label>
                    <input pInputText id="branch" [(ngModel)]="form.branch" placeholder="main" />
                </div>
                <div class="flex flex-col gap-2">
                    <label for="name" class="font-medium">Display name <span class="text-muted-color font-normal">(optional)</span></label>
                    <input pInputText id="name" [(ngModel)]="form.name" />
                </div>
                <div class="flex flex-col gap-2">
                    <label for="sub-path" class="font-medium">Sub-path <span class="text-muted-color font-normal">(optional)</span></label>
                    <input pInputText id="sub-path" [(ngModel)]="form.subPath" placeholder="services/billing" />
                    <small class="text-muted-color">
                        The directory to analyse, when only part of the repository is a project. Leave empty for the
                        whole thing. <strong>A monorepo is registered once per project</strong>: add the same URL again
                        with another sub-path, and give each a display name — the two are scanned, triaged and gated
                        independently, which is the point.
                    </small>
                </div>
                <div class="flex flex-col gap-2">
                    <label for="agent-label" class="font-medium">Required agent <span class="text-muted-color font-normal">(optional)</span></label>
                    <input pInputText id="agent-label" [(ngModel)]="form.requiredAgentLabel" placeholder="customer-network" />
                    <small class="text-muted-color">
                        The label an agent must carry to scan this target — and therefore to receive
                        its deployment key. Left empty, any agent may take it.
                    </small>
                </div>
                @if (formError(); as message) {
                    <p-message severity="error" [closable]="false">{{ message }}</p-message>
                }
            </div>
            <ng-template #footer>
                <p-button label="Cancel" [text]="true" (onClick)="formVisible.set(false)" />
                <p-button [label]="editing() ? 'Save' : 'Add'" [loading]="saving()" (onClick)="submit()" />
            </ng-template>
        </p-dialog>

        <p-dialog header="Delete this repository?" [(visible)]="deleteVisible" [modal]="true" [style]="{ width: '30rem' }">
            @if (pendingDelete(); as repository) {
                <p class="m-0">
                    <span class="font-medium">{{ repository.url }}</span> and its whole history — scans, findings and
                    {{ repository.openIssues }} outstanding issue(s) — will be deleted. This is permanent.
                </p>
            }
            <ng-template #footer>
                <p-button label="Cancel" [text]="true" (onClick)="deleteVisible.set(false)" />
                <p-button label="Delete" severity="danger" [loading]="saving()" (onClick)="confirmDelete()" />
            </ng-template>
        </p-dialog>
    `
})
export class Repositories {
    private readonly api = inject(ApiService);
    private readonly session = inject(SessionStore);

    readonly repositories = signal<MonitoredRepository[]>([]);
    readonly loading = signal(true);
    readonly saving = signal(false);
    readonly error = signal<string | null>(null);
    readonly formError = signal<string | null>(null);
    readonly formVisible = signal(false);
    readonly deleteVisible = signal(false);
    readonly pendingDelete = signal<MonitoredRepository | null>(null);
    /** La ligne dont le scan est en cours de mise en file. */
    readonly busy = signal<number | null>(null);
    readonly notice = signal<string | null>(null);
    readonly isAdmin = this.session.isAdmin;

    form = { url: '', branch: 'main', name: '', subPath: '', requiredAgentLabel: '' };

    /** The row being edited, or null when the dialog is adding one. */
    readonly editing = signal<MonitoredRepository | null>(null);

    constructor() {
        this.reload();
    }

    reload(): void {
        this.loading.set(true);
        this.api.repositories().subscribe({
            next: (repositories) => {
                this.repositories.set(repositories);
                this.error.set(null);
                this.loading.set(false);
            },
            error: () => {
                this.error.set('Could not load the repository list.');
                this.loading.set(false);
            }
        });
    }

    /**
     * Queues a scan. **It does not run it**: a worker will claim it.
     *
     * The screen says so, because the wait that follows is not an ordinary button's — without
     * that sentence, the absence of an immediate change reads as a failure.
     */
    triggerScan(repository: MonitoredRepository): void {
        this.busy.set(repository.id);
        this.notice.set(null);
        this.api.triggerRepositoryScan(repository.id).subscribe({
            next: () => {
                this.busy.set(null);
                this.notice.set(`Scan queued for ${repository.displayName}. It will start as soon as a worker is available.`);
                this.reload();
            },
            error: (response) => {
                this.busy.set(null);
                // The server knows why — "a scan is already queued", most of the time.
                this.error.set(messageOf(response, 'Could not queue this scan.'));
            }
        });
    }

    openForm(repository?: MonitoredRepository): void {
        this.editing.set(repository ?? null);
        this.form = repository
            ? {
                  url: repository.url,
                  branch: repository.branch,
                  name: repository.name ?? '',
                  subPath: repository.subPath ?? '',
                  requiredAgentLabel: repository.requiredAgentLabel ?? ''
              }
            : { url: '', branch: 'main', name: '', subPath: '', requiredAgentLabel: '' };
        this.formError.set(null);
        this.formVisible.set(true);
    }

    submit(): void {
        const editing = this.editing();
        // **Empty string and not `undefined` when editing.** On the create path an absent field
        // means "no value"; on the update path the server reads absent as "leave alone", so a
        // field the operator cleared has to be sent as empty or the clearing is silently
        // dropped — the form would show it gone and the next scan would disagree.
        const blank = editing ? '' : undefined;
        const body = {
            url: this.form.url.trim(),
            branch: this.form.branch.trim() || 'main',
            name: this.form.name.trim() || blank,
            subPath: this.form.subPath.trim() || blank,
            required_agent_label: this.form.requiredAgentLabel.trim() || blank
        };

        this.saving.set(true);
        const call = editing ? this.api.updateRepository(editing.id, body) : this.api.createRepository(body);
        call.subscribe({
            next: () => {
                this.saving.set(false);
                this.formVisible.set(false);
                this.editing.set(null);
                this.reload();
            },
            error: (response) => {
                this.saving.set(false);
                // The server's message is the one that knows *why* — scheme refused, host
                // missing. Replacing it with a generic "error" would lose that.
                this.formError.set(messageOf(response, editing ? 'Could not save this repository.' : 'Could not add this repository.'));
            }
        });
    }

    askDelete(repository: MonitoredRepository): void {
        this.pendingDelete.set(repository);
        this.deleteVisible.set(true);
    }

    confirmDelete(): void {
        const repository = this.pendingDelete();
        if (!repository) return;
        this.saving.set(true);
        this.api.deleteRepository(repository.id).subscribe({
            next: () => {
                this.saving.set(false);
                this.deleteVisible.set(false);
                this.reload();
            },
            error: () => {
                this.saving.set(false);
                this.deleteVisible.set(false);
                this.error.set('The deletion failed.');
            }
        });
    }


}
