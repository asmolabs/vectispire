import { DatePipe } from '@angular/common';
import { I18nService } from '../../core/i18n/i18n.service';
import { Component, computed, inject, signal, ChangeDetectionStrategy } from '@angular/core';
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
import { TargetsApi } from '../../core/api/targets.api';
import type { SshKeySummary } from '../../core/api.models';

/**
 * The encryption state deserves a column, not a log line.
 *
 * A key readable only under a previous encryption key has not finished being rotated. A key
 * that no configured key reads will fail the next clone that needs it — at scan time, on a
 * worker thread, hours later, with a message that will look like a network problem.
 */

import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { encryptionBadge, SSH_KEY_HINT_KEYS } from '../../shared/encryption-state';

@Component({
    selector: 'app-ssh-keys',
    imports: [
        DatePipe,
        FormsModule,
        ButtonModule,
        CardModule,
        DialogModule,
        InputTextModule,
        MessageModule,
        TableModule,
        TagModule,
        TextareaModule,
        TooltipModule,
        TranslatePipe
    ],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './ssh-keys.html'
})
export class SshKeys {
    private readonly i18n = inject(I18nService);
    private readonly targetsApi = inject(TargetsApi);

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
        this.targetsApi.sshKeys().subscribe({
            next: (keys) => {
                this.keys.set(keys);
                this.error.set(null);
                this.loading.set(false);
            },
            error: () => {
                this.error.set(this.i18n.t('ssh_keys.error_load'));
                this.loading.set(false);
            }
        });
    }

    /**
     * Each key with its badge and its shortened public key worked out once — per list or language,
     * not three badges per row on every pass. `t` reads the bundle's signal, so a switch recomputes them.
     */
    readonly rows = computed(() =>
        this.keys().map((key) => ({
            ...key,
            badge: encryptionBadge(this.i18n, key.encryptionState, SSH_KEY_HINT_KEYS),
            shortKey: key.publicKey ? shorten(key.publicKey) : null
        }))
    );

    openForm(): void {
        this.form = { name: '', privateKey: '', publicKey: '' };
        this.formError.set(null);
        this.formVisible.set(true);
    }

    submit(): void {
        // Enter in a field submits the form too: one request at a time.
        if (this.saving()) return;
        this.saving.set(true);
        this.targetsApi
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
                    this.formError.set(messageOf(response, this.i18n.t('ssh_keys.error_add')));
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
        this.targetsApi.deleteSshKey(key.id).subscribe({
            next: () => {
                this.saving.set(false);
                this.deleteVisible.set(false);
                this.reload();
            },
            error: (response) => {
                this.saving.set(false);
                this.deleteVisible.set(false);
                // Notably "used by N repositories": the refusal carries the number to detach.
                this.error.set(messageOf(response, this.i18n.t('ssh_keys.error_delete')));
            }
        });
    }
}

/** A public key runs to a 400-character line: shortened, like image digests, or it crushes every other column. */
function shorten(value: string): string {
    return value.length > 44 ? `${value.slice(0, 44)}…` : value;
}
