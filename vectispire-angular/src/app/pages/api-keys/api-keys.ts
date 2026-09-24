import { CommonModule } from '@angular/common';
import { I18nService } from '../../core/i18n/i18n.service';
import { Component, computed, inject, signal, ChangeDetectionStrategy } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { CheckboxModule } from '@openng/optimus-ui/checkbox';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { InputNumberModule } from '@openng/optimus-ui/inputnumber';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { SelectModule } from '@openng/optimus-ui/select';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import { messageOf } from '../../core/api-error';
import { AccountsApi } from '../../core/api/accounts.api';
import type { ApiKeySummary, ApiKeyTargets } from '../../core/api.models';

/** The scopes, with what they allow — because "scan" and "agent" look alike and one of the two
 *  grants the right to execute code. */

/** One side of the target list, or nothing at all: a missing or non-array side means that kind of
 *  target simply is not offered, which is the degraded-but-usable state the form expects. */
function optionsOf(rows: { id: number; label: string }[] | undefined, prefix: string, kind: string) {
    if (!Array.isArray(rows)) return [];
    return rows.map((row) => ({ label: `${prefix} — ${row.label}`, value: `${kind}:${row.id}` }));
}

import { TranslatePipe } from '../../core/i18n/translate.pipe';

@Component({
    selector: 'app-api-keys',
    standalone: true,
    imports: [CommonModule, FormsModule, ButtonModule, CardModule, CheckboxModule, DialogModule, InputNumberModule, InputTextModule, MessageModule, SelectModule, TableModule, TagModule, TranslatePipe],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './api-keys.html'
})
export class ApiKeys {
    private readonly i18n = inject(I18nService);
    private readonly accountsApi = inject(AccountsApi);
    readonly scopes = computed(() => {
        this.i18n.translations();
        return [
            { value: 'read', label: this.i18n.t('api_keys.scopes_list.read'), hint: this.i18n.t('api_keys.scopes_list.read_hint') },
            { value: 'scan', label: this.i18n.t('api_keys.scopes_list.scan'), hint: this.i18n.t('api_keys.scopes_list.scan_hint') },
            { value: 'export', label: this.i18n.t('api_keys.scopes_list.export'), hint: this.i18n.t('api_keys.scopes_list.export_hint') },
            { value: 'agent', label: this.i18n.t('api_keys.scopes_list.agent'), hint: this.i18n.t('api_keys.scopes_list.agent_hint') }
        ];
    });

    readonly keys = signal<ApiKeySummary[]>([]);
    /** Kept raw: the prefixes are translated at render time, so a language switch relabels them. */
    private readonly targets = signal<ApiKeyTargets | null>(null);
    readonly targetOptions = computed(() => {
        this.i18n.translations();
        const targets = this.targets();
        return [
            ...optionsOf(targets?.repositories, this.i18n.t('api_keys.target_repository_prefix'), 'repository'),
            ...optionsOf(targets?.containers, this.i18n.t('api_keys.target_container_prefix'), 'container')
        ];
    });
    readonly loading = signal(true);
    readonly saving = signal(false);
    readonly error = signal<string | null>(null);
    readonly formError = signal<string | null>(null);
    readonly formVisible = signal(false);
    readonly secretVisible = signal(false);
    readonly issuedSecret = signal<string | null>(null);
    readonly deleteVisible = signal(false);
    readonly pendingDelete = signal<ApiKeySummary | null>(null);

    form: { name: string; scopes: string[]; target: string | null; expiresInDays: number | null } = {
        name: '',
        scopes: ['read', 'scan', 'export'],
        target: null,
        expiresInDays: null
    };

    constructor() {
        this.reload();
        this.accountsApi.apiKeyTargets().subscribe({
            // Each side is read defensively: an `error:` handler catches an HTTP failure, not an
            // exception thrown here, so a payload missing one of the two arrays used to escape as
            // an uncaught TypeError instead of taking the degraded path promised below.
            next: (targets) => this.targets.set(targets ?? null),
            // Silent: without the list the field stays empty and the key covers every target.
            // That is degraded, not broken — no reason to alarm anybody.
            error: () => this.targets.set(null)
        });
    }

    reload(preserveError = false): void {
        this.loading.set(true);
        this.accountsApi.apiKeys().subscribe({
            next: (keys) => {
                this.keys.set(keys);
                if (!preserveError) this.error.set(null);
                this.loading.set(false);
            },
            error: () => {
                this.error.set(this.i18n.t('api_keys.error_load'));
                this.loading.set(false);
            }
        });
    }

    scopeLabel(scope: string): string {
        return this.scopes().find((entry) => entry.value === scope)?.label ?? scope;
    }

    toggleScope(scope: string, checked: boolean): void {
        this.form.scopes = checked ? [...this.form.scopes, scope] : this.form.scopes.filter((value) => value !== scope);
    }

    openForm(): void {
        this.form = { name: '', scopes: ['read', 'scan', 'export'], target: null, expiresInDays: null };
        this.formError.set(null);
        this.formVisible.set(true);
    }

    submit(): void {
        const [targetKind, targetId] = this.form.target ? this.form.target.split(':') : [undefined, undefined];
        this.saving.set(true);
        this.accountsApi
            .createApiKey({
                name: this.form.name.trim(),
                scopes: this.form.scopes,
                target_kind: targetKind,
                target_id: targetId === undefined ? undefined : Number(targetId),
                expires_in_days: this.form.expiresInDays ?? undefined
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
                    this.formError.set(messageOf(response, this.i18n.t('api_keys.error_issue')));
                }
            });
    }

    dismissSecret(): void {
        // Cleared from the model at the same time as from the screen: keeping it in memory for
        // laisserait la valeur accessible dans l'onglet ouvert.
        this.issuedSecret.set(null);
        this.secretVisible.set(false);
    }

    askDelete(key: ApiKeySummary): void {
        this.pendingDelete.set(key);
        this.deleteVisible.set(true);
    }

    confirmDelete(): void {
        const key = this.pendingDelete();
        if (!key) return;
        this.saving.set(true);
        this.accountsApi.deleteApiKey(key.id).subscribe({
            next: () => {
                this.saving.set(false);
                this.deleteVisible.set(false);
                this.reload();
            },
            error: (response) => {
                this.saving.set(false);
                this.deleteVisible.set(false);
                this.error.set(messageOf(response, this.i18n.t('api_keys.error_revoke')));
                this.reload(true);
            }
        });
    }
}
