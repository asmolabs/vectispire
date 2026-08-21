import { CommonModule } from '@angular/common';
import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { DataViewModule } from '@openng/optimus-ui/dataview';
import { messageOf } from '../../core/api-error';
import { ApiService } from '../../core/api.service';
import type { MonitoredContainer } from '../../core/api.models';
import { SessionStore } from '../../core/session.store';
import { LastScanTag } from '../../shared/last-scan';

@Component({
    selector: 'app-containers',
    standalone: true,
    imports: [CommonModule, FormsModule, RouterLink, ButtonModule, CardModule, DialogModule, InputTextModule, MessageModule, DataViewModule, LastScanTag],
    templateUrl: './containers.html'
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
                this.error.set(messageOf(response, 'Could not queue this scan.'));
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
                    this.formError.set(messageOf(response, 'Could not add this image.'));
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
