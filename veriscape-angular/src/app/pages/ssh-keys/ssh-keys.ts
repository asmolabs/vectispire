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

import { TranslatePipe } from '../../core/i18n/translate.pipe';

@Component({
    selector: 'app-ssh-keys',
    standalone: true,
    imports: [CommonModule, FormsModule, ButtonModule, CardModule, DialogModule, InputTextModule, MessageModule, TableModule, TagModule, TextareaModule, TooltipModule, TranslatePipe],
    templateUrl: './ssh-keys.html'
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
