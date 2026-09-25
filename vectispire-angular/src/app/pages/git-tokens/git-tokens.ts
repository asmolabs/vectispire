import { CommonModule } from '@angular/common';
import { Component, inject, signal, ChangeDetectionStrategy } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import { TooltipModule } from '@openng/optimus-ui/tooltip';
import { messageOf } from '../../core/api-error';
import { TargetsApi } from '../../core/api/targets.api';
import type { EncryptionState, GitTokenSummary } from '../../core/api.models';
import { I18nService } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';

/**
 * The HTTPS clone tokens, beside the SSH keys and built the same way.
 *
 * **The host is a column because it is the token's boundary** (decision 0022): the server sends the
 * token to that host and to no other, so a repository on another host cannot borrow it. Before
 * this screen the only way to clone over HTTPS was a token pasted into the URL — stored in clear,
 * shown on every list, and sent wherever the URL was later edited to point.
 */
@Component({
    selector: 'app-git-tokens',
    standalone: true,
    imports: [
        CommonModule,
        FormsModule,
        ButtonModule,
        CardModule,
        DialogModule,
        InputTextModule,
        MessageModule,
        TableModule,
        TagModule,
        TooltipModule,
        TranslatePipe
    ],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './git-tokens.html'
})
export class GitTokens {
    private readonly i18n = inject(I18nService);
    private readonly targetsApi = inject(TargetsApi);

    readonly tokens = signal<GitTokenSummary[]>([]);
    readonly loading = signal(true);
    readonly saving = signal(false);
    readonly error = signal<string | null>(null);
    readonly formError = signal<string | null>(null);
    readonly formVisible = signal(false);
    readonly deleteVisible = signal(false);
    readonly pendingDelete = signal<GitTokenSummary | null>(null);

    form = GitTokens.emptyForm();

    private static emptyForm() {
        return { name: '', host: '', username: '', token: '' };
    }

    constructor() {
        this.reload();
    }

    reload(): void {
        this.loading.set(true);
        this.targetsApi.gitTokens().subscribe({
            next: (tokens) => {
                this.tokens.set(tokens);
                this.error.set(null);
                this.loading.set(false);
            },
            error: () => {
                this.error.set(this.i18n.t('git_tokens.error_load'));
                this.loading.set(false);
            }
        });
    }

    badge(state: EncryptionState) {
        const severities: Record<EncryptionState, 'success' | 'warn' | 'danger'> = {
            current: 'success',
            previous_key: 'warn',
            unreadable: 'danger'
        };
        // Anything unknown reads as unreadable: a healthy badge on a value nobody recognises would
        // be the one wrong answer that hides a failing clone.
        const key: EncryptionState = state in severities ? state : 'unreadable';
        return {
            label: this.i18n.t(`ssh_keys.encryption_status.${key === 'previous_key' ? 'rotate' : key}`),
            severity: severities[key],
            hint: this.i18n.t(`git_tokens.encryption_status.${key}_hint`)
        };
    }

    openForm(): void {
        this.form = GitTokens.emptyForm();
        this.formError.set(null);
        this.formVisible.set(true);
    }

    /**
     * Closing the dialog forgets what was typed, the token first.
     *
     * The dialog is only hidden, not destroyed, so without this a cancelled token would sit in the
     * component — and in the input, for the next person to open the form — for as long as the page
     * stays open. The session token lives in memory only; a clone token should not live longer.
     */
    closeForm(): void {
        this.form = GitTokens.emptyForm();
        this.formVisible.set(false);
    }

    submit(): void {
        this.saving.set(true);
        this.targetsApi
            .createGitToken({
                name: this.form.name.trim(),
                // A bare host name only; the server says why when it is not one (scheme, port,
                // path), and duplicating that parser here would mean two rules to keep agreeing.
                host: this.form.host.trim(),
                username: this.form.username.trim() || undefined,
                token: this.form.token.trim()
            })
            .subscribe({
                next: () => {
                    this.saving.set(false);
                    this.closeForm();
                    this.reload();
                },
                error: (response) => {
                    this.saving.set(false);
                    // Kept while the dialog is open so a host typo can be fixed without pasting
                    // the token again; `closeForm` forgets it either way.
                    this.formError.set(messageOf(response, this.i18n.t('git_tokens.error_add')));
                }
            });
    }

    askDelete(token: GitTokenSummary): void {
        this.pendingDelete.set(token);
        this.deleteVisible.set(true);
    }

    confirmDelete(): void {
        const token = this.pendingDelete();
        if (!token) return;
        this.saving.set(true);
        this.targetsApi.deleteGitToken(token.id).subscribe({
            next: () => {
                this.saving.set(false);
                this.deleteVisible.set(false);
                this.reload();
            },
            error: (response) => {
                this.saving.set(false);
                this.deleteVisible.set(false);
                // Notably "still used by a repository": the server names what to detach first.
                this.error.set(messageOf(response, this.i18n.t('git_tokens.error_delete')));
            }
        });
    }
}
