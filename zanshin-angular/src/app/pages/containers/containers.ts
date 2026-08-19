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
import { ApiService } from '../../core/api.service';
import type { MonitoredContainer } from '../../core/api.models';
import { SessionStore } from '../../core/session.store';
import { LastScanTag } from '../../shared/last-scan';

@Component({
    selector: 'app-containers',
    standalone: true,
    imports: [CommonModule, FormsModule, RouterLink, ButtonModule, CardModule, DialogModule, InputTextModule, MessageModule, TableModule, LastScanTag],
    template: `
        <div class="mb-4 flex items-start justify-between gap-4">
            <div>
                <h1 class="text-2xl font-semibold m-0">Containers</h1>
                <p class="text-muted-color mt-1 mb-0">The monitored container images and the state of their last scan.</p>
            </div>
            @if (isAdmin()) {
                <p-button label="Add an image" icon="pi pi-plus" (onClick)="openForm()" />
            }
        </div>

        @if (error(); as message) {
            <p-message severity="error" [closable]="false" styleClass="mb-4 w-full">{{ message }}</p-message>
        }
        @if (notice(); as message) {
            <p-message severity="success" [closable]="false" styleClass="mb-4 w-full">{{ message }}</p-message>
        }

        <p-card>
            <p-table [value]="containers()" [loading]="loading()" dataKey="id" styleClass="p-datatable-sm">
                <ng-template #header>
                    <tr>
                        <th>Image</th>
                        <th>Tag</th>
                        <th>Dernier scan</th>
                        <th class="text-right">Outstanding</th>
                        @if (isAdmin()) { <th class="w-1"></th> }
                    </tr>
                </ng-template>
                <ng-template #body let-container>
                    <tr>
                        <td>
                            <div class="font-medium">{{ container.imageName }}</div>
                            <div class="text-sm text-muted-color" [title]="container.reference">{{ shorten(container.reference) }}</div>
                        </td>
                        <td class="font-mono text-sm whitespace-nowrap" [title]="container.tag">{{ shorten(container.tag) }}</td>
                        <td><app-last-scan [scan]="container.lastScan" /></td>
                        <td class="text-right">
                            @if (container.openIssues > 0) {
                                <a [routerLink]="['/issues']" [queryParams]="{ container_id: container.id }" class="font-medium">{{ container.openIssues }}</a>
                            } @else {
                                <span class="text-muted-color">0</span>
                            }
                        </td>
                        @if (isAdmin()) {
                            <td class="text-right whitespace-nowrap">
                                <p-button icon="pi pi-play" [text]="true" [rounded]="true"
                                          [ariaLabel]="'Run a scan of ' + container.reference"
                                          [disabled]="busy() === container.id" (onClick)="triggerScan(container)" />
                                <p-button icon="pi pi-trash" severity="danger" [text]="true" [rounded]="true"
                                          [ariaLabel]="'Delete ' + container.reference" (onClick)="askDelete(container)" />
                            </td>
                        }
                    </tr>
                </ng-template>
                <ng-template #emptymessage>
                    <tr><td [attr.colspan]="isAdmin() ? 5 : 4" class="text-center text-muted-color py-6">No monitored image.</td></tr>
                </ng-template>
            </p-table>
        </p-card>

        <p-dialog header="Add an image" [(visible)]="formVisible" [modal]="true" [style]="{ width: '32rem' }">
            <div class="flex flex-col gap-4">
                <div class="flex flex-col gap-2">
                    <label for="registry" class="font-medium">Registry <span class="text-muted-color font-normal">(optional)</span></label>
                    <input pInputText id="registry" [(ngModel)]="form.registry" placeholder="ghcr.io" />
                    <small class="text-muted-color">Empty for the default registry.</small>
                </div>
                <div class="flex flex-col gap-2">
                    <label for="image" class="font-medium">Image name</label>
                    <input pInputText id="image" [(ngModel)]="form.imageName" placeholder="team/service" />
                </div>
                <div class="flex flex-col gap-2">
                    <label for="tag" class="font-medium">Tag</label>
                    <input pInputText id="tag" [(ngModel)]="form.tag" placeholder="latest" />
                    <small class="text-muted-color">A tag, or a "sha256:…" digest to pin the version that gets scanned.</small>
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
                <p-button label="Add" [loading]="saving()" (onClick)="submit()" />
            </ng-template>
        </p-dialog>

        <p-dialog header="Delete this image?" [(visible)]="deleteVisible" [modal]="true" [style]="{ width: '30rem' }">
            @if (pendingDelete(); as container) {
                <p class="m-0">
                    <span class="font-medium">{{ container.reference }}</span> and its whole history — scans, findings and
                    {{ container.openIssues }} outstanding issue(s) — will be deleted. This is permanent.
                </p>
            }
            <ng-template #footer>
                <p-button label="Cancel" [text]="true" (onClick)="deleteVisible.set(false)" />
                <p-button label="Delete" severity="danger" [loading]="saving()" (onClick)="confirmDelete()" />
            </ng-template>
        </p-dialog>
    `
})
export class Containers {
    private readonly api = inject(ApiService);
    private readonly session = inject(SessionStore);

    readonly containers = signal<MonitoredContainer[]>([]);
    readonly loading = signal(true);
    readonly saving = signal(false);
    readonly error = signal<string | null>(null);
    /** La ligne dont le scan est en cours de mise en file. */
    readonly busy = signal<number | null>(null);
    readonly notice = signal<string | null>(null);
    readonly formError = signal<string | null>(null);
    readonly formVisible = signal(false);
    readonly deleteVisible = signal(false);
    readonly pendingDelete = signal<MonitoredContainer | null>(null);
    readonly isAdmin = this.session.isAdmin;

    form = { registry: '', imageName: '', tag: 'latest', requiredAgentLabel: '' };

    /**
     * Shortens a digest for display, the whole value staying in the tooltip.
     *
     * Without this the 64 hexadecimal characters widen their column until they crush every
     * other one — the table becomes unreadable for *all* containers as soon as a single one is
     * pinned by digest. It only shows on screen.
     */
    shorten(value: string): string {
        const match = /sha256:([a-f0-9]{64})/.exec(value);
        return match ? value.replace(match[1], match[1].slice(0, 12) + '…') : value;
    }

    constructor() {
        this.reload();
    }

    /**
     * Queues a scan. **It does not run it**: a worker will claim it.
     *
     * The screen says so, because the wait that follows is not an ordinary button's — without
     * that sentence, the absence of an immediate change reads as a failure. For an image it is
     * truer still than for a repository: it has to be pulled from the registry first.
     */
    triggerScan(container: MonitoredContainer): void {
        this.busy.set(container.id);
        this.notice.set(null);
        this.api.triggerContainerScan(container.id).subscribe({
            next: () => {
                this.busy.set(null);
                this.notice.set(`Scan queued for ${container.reference}. It will start as soon as a worker is available.`);
                this.reload();
            },
            error: (response) => {
                this.busy.set(null);
                // The server knows why — "a scan is already queued", most of the time.
                this.error.set(response?.error?.message ?? 'Could not queue this scan.');
            }
        });
    }

    reload(): void {
        this.loading.set(true);
        this.api.containers().subscribe({
            next: (containers) => {
                this.containers.set(containers);
                this.error.set(null);
                this.loading.set(false);
            },
            error: () => {
                this.error.set('Could not load the container list.');
                this.loading.set(false);
            }
        });
    }

    openForm(): void {
        this.form = { registry: '', imageName: '', tag: 'latest', requiredAgentLabel: '' };
        this.formError.set(null);
        this.formVisible.set(true);
    }

    submit(): void {
        this.saving.set(true);
        this.api
            .createContainer({
                registry: this.form.registry.trim() || undefined,
                image_name: this.form.imageName.trim(),
                tag: this.form.tag.trim() || 'latest',
                required_agent_label: this.form.requiredAgentLabel.trim() || undefined
            })
            .subscribe({
                next: () => {
                    this.saving.set(false);
                    this.formVisible.set(false);
                    this.reload();
                },
                error: (response) => {
                    this.saving.set(false);
                    // The server's message is the one that knows *why* — upper case refused,
                    // malformed digest. Replacing it would lose the information.
                    this.formError.set(response?.error?.message ?? 'Could not add this image.');
                }
            });
    }

    askDelete(container: MonitoredContainer): void {
        this.pendingDelete.set(container);
        this.deleteVisible.set(true);
    }

    confirmDelete(): void {
        const container = this.pendingDelete();
        if (!container) return;
        this.saving.set(true);
        this.api.deleteContainer(container.id).subscribe({
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
