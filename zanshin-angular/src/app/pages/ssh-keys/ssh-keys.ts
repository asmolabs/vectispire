import { CommonModule } from '@angular/common';
import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import { TextareaModule } from '@openng/optimus-ui/textarea';
import { TooltipModule } from '@openng/optimus-ui/tooltip';
import { messageOf } from '../../core/api-error';
import { ApiService } from '../../core/api.service';
import type { EncryptionState, SshKeySummary } from '../../core/api.models';

/**
 * The encryption state deserves a column, not a log line.
 *
 * A key readable only under a previous encryption key has not finished being rotated. A key
 * that no configured key reads will fail the next clone that needs it — at scan time, on a
 * worker thread, hours later, with a message that will look like a network problem.
 */
const ENCRYPTION_LABELS: Record<EncryptionState, { label: string; severity: 'success' | 'warn' | 'danger'; hint: string }> = {
    current: { label: 'OK', severity: 'success', hint: 'Encrypted with the current encryption key.' },
    previous_key: {
        label: 'Rotate',
        severity: 'warn',
        hint:
            'Encrypted with a previous encryption key. Save it again to move it under ENCRYPTION_KEY — ' +
            'and if it dates from the default key published in the repository, its private half is public: generate a new pair.'
    },
    unreadable: {
        label: 'Unreadable',
        severity: 'danger',
        hint:
            'No configured key decrypts this value: the next clone that needs it will fail. ' +
            'Add the previous key to ZANSHIN_PREVIOUS_ENCRYPTION_KEYS, or replace this SSH key.'
    }
};

@Component({
    selector: 'app-ssh-keys',
    standalone: true,
    imports: [CommonModule, FormsModule, ButtonModule, CardModule, DialogModule, InputTextModule, MessageModule, TableModule, TagModule, TextareaModule, TooltipModule],
    template: `
        <div class="mb-4 flex items-start justify-between gap-4">
            <div>
                <h1 class="text-2xl font-semibold m-0">SSH keys</h1>
                <p class="text-muted-color mt-1 mb-0">The deployment keys used to clone private repositories.</p>
            </div>
            <p-button label="Add a key" icon="pi pi-plus" (onClick)="openForm()" />
        </div>

        <!-- Says what is missing rather than offering a button that would produce a pair we
             cannot check here that a git server accepts. -->
        <p-message severity="info" [closable]="false" styleClass="mb-4 w-full">
            Generating a pair from the interface is not ported yet. Generate one with
            <span class="font-mono">ssh-keygen -t ed25519</span>, then paste the private half here.
        </p-message>

        @if (error(); as message) {
            <p-message severity="error" [closable]="false" styleClass="mb-4 w-full">{{ message }}</p-message>
        }

        <p-card>
            <p-table [value]="keys()" [loading]="loading()" dataKey="id" styleClass="p-datatable-sm">
                <ng-template #header>
                    <tr>
                        <th>Name</th>
                        <th>Public key</th>
                        <th>Encryption</th>
                        <th>Added</th>
                        <th class="text-right">Repositories</th>
                        <th class="w-1"></th>
                    </tr>
                </ng-template>
                <ng-template #body let-key>
                    <tr>
                        <td class="font-medium">{{ key.name }}</td>
                        <td>
                            @if (key.publicKey) {
                                <span class="font-mono text-sm whitespace-nowrap" [title]="key.publicKey">{{ shorten(key.publicKey) }}</span>
                            } @else {
                                <span class="text-muted-color">—</span>
                            }
                        </td>
                        <td>
                            <p-tag [value]="badge(key.encryptionState).label" [severity]="badge(key.encryptionState).severity"
                                   [pTooltip]="badge(key.encryptionState).hint" tooltipPosition="top" />
                        </td>
                        <td>{{ key.createdAt | date: 'dd/MM/yyyy HH:mm' }}</td>
                        <td class="text-right">{{ key.usedByRepositories }}</td>
                        <td class="text-right">
                            <p-button icon="pi pi-trash" severity="danger" [text]="true" [rounded]="true"
                                      [ariaLabel]="'Delete ' + key.name" (onClick)="askDelete(key)" />
                        </td>
                    </tr>
                </ng-template>
                <ng-template #emptymessage>
                    <tr><td colspan="6" class="text-center text-muted-color py-6">No key registered.</td></tr>
                </ng-template>
            </p-table>
        </p-card>

        <p-dialog header="Add an SSH key" [(visible)]="formVisible" [modal]="true" [style]="{ width: '40rem' }">
            <div class="flex flex-col gap-4">
                <div class="flex flex-col gap-2">
                    <label for="name" class="font-medium">Nom</label>
                    <input pInputText id="name" [(ngModel)]="form.name" placeholder="GitHub deployment" />
                </div>
                <div class="flex flex-col gap-2">
                    <label for="private" class="font-medium">Private key</label>
                    <textarea pTextarea id="private" [(ngModel)]="form.privateKey" rows="7" class="font-mono text-sm"
                              placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"></textarea>
                    <small class="text-muted-color">Encrypted before it is written, and never shown again.</small>
                </div>
                <div class="flex flex-col gap-2">
                    <label for="public" class="font-medium">Public key <span class="text-muted-color font-normal">(optional)</span></label>
                    <textarea pTextarea id="public" [(ngModel)]="form.publicKey" rows="2" class="font-mono text-sm"
                              placeholder="ssh-ed25519 AAAA…"></textarea>
                    <small class="text-muted-color">Useful for finding which key to register with the provider.</small>
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

        <p-dialog header="Delete this key?" [(visible)]="deleteVisible" [modal]="true" [style]="{ width: '30rem' }">
            @if (pendingDelete(); as key) {
                <p class="m-0"><span class="font-medium">{{ key.name }}</span> will be deleted. This is permanent.</p>
            }
            <ng-template #footer>
                <p-button label="Cancel" [text]="true" (onClick)="deleteVisible.set(false)" />
                <p-button label="Delete" severity="danger" [loading]="saving()" (onClick)="confirmDelete()" />
            </ng-template>
        </p-dialog>
    `
})
export class SshKeys {
    private readonly api = inject(ApiService);

    readonly keys = signal<SshKeySummary[]>([]);
    readonly loading = signal(true);
    readonly saving = signal(false);
    readonly error = signal<string | null>(null);
    readonly formError = signal<string | null>(null);
    readonly formVisible = signal(false);
    readonly deleteVisible = signal(false);
    readonly pendingDelete = signal<SshKeySummary | null>(null);

    form = { name: '', privateKey: '', publicKey: '' };

    constructor() {
        this.reload();
    }

    reload(): void {
        this.loading.set(true);
        this.api.sshKeys().subscribe({
            next: (keys) => {
                this.keys.set(keys);
                this.error.set(null);
                this.loading.set(false);
            },
            error: () => {
                this.error.set('Could not load the key list.');
                this.loading.set(false);
            }
        });
    }

    badge(state: EncryptionState) {
        return ENCRYPTION_LABELS[state] ?? ENCRYPTION_LABELS.unreadable;
    }

    /** A public key runs to a 400-character line: shortened, like image digests, or it
     *  crushes every other column. */
    shorten(value: string): string {
        return value.length > 44 ? `${value.slice(0, 44)}…` : value;
    }

    openForm(): void {
        this.form = { name: '', privateKey: '', publicKey: '' };
        this.formError.set(null);
        this.formVisible.set(true);
    }

    submit(): void {
        this.saving.set(true);
        this.api
            .createSshKey({
                name: this.form.name.trim(),
                private_key: this.form.privateKey.trim(),
                public_key: this.form.publicKey.trim() || undefined
            })
            .subscribe({
                next: () => {
                    this.saving.set(false);
                    this.formVisible.set(false);
                    this.reload();
                },
                error: (response) => {
                    this.saving.set(false);
                    // The server knows *why* — not a private key, no encryption key configured.
                    // A generic message would lose the action to take.
                    this.formError.set(messageOf(response, 'Could not add this key.'));
                }
            });
    }

    askDelete(key: SshKeySummary): void {
        this.pendingDelete.set(key);
        this.deleteVisible.set(true);
    }

    confirmDelete(): void {
        const key = this.pendingDelete();
        if (!key) return;
        this.saving.set(true);
        this.api.deleteSshKey(key.id).subscribe({
            next: () => {
                this.saving.set(false);
                this.deleteVisible.set(false);
                this.reload();
            },
            error: (response) => {
                this.saving.set(false);
                this.deleteVisible.set(false);
                // Notably "used by N repositories": the refusal carries the number to detach.
                this.error.set(messageOf(response, 'The deletion failed.'));
            }
        });
    }
}
