import { CommonModule } from '@angular/common';
import { Component, inject, signal } from '@angular/core';
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
import { ApiService } from '../../core/api.service';
import type { ApiKeySummary } from '../../core/api.models';

/** The scopes, with what they allow — because "scan" and "agent" look alike and one of the two
 *  grants the right to execute code. */
const SCOPES = [
    { value: 'read', label: 'Read', hint: 'View findings, scans and reports.' },
    { value: 'scan', label: 'Trigger a scan', hint: 'Queue a scan on an existing target.' },
    { value: 'export', label: 'Export', hint: 'Retrieve SARIF, OpenVEX, SBOM.' },
    { value: 'agent', label: 'Agent', hint: 'Claim and run scans. This scope executes code: grant it only to an agent.' }
];

@Component({
    selector: 'app-api-keys',
    standalone: true,
    imports: [CommonModule, FormsModule, ButtonModule, CardModule, CheckboxModule, DialogModule, InputNumberModule, InputTextModule, MessageModule, SelectModule, TableModule, TagModule],
    templateUrl: './api-keys.html'
})
export class ApiKeys {
    private readonly api = inject(ApiService);
    readonly scopes = SCOPES;

    readonly keys = signal<ApiKeySummary[]>([]);
    readonly targetOptions = signal<{ label: string; value: string }[]>([]);
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
        this.api.apiKeyTargets().subscribe({
            next: (targets) => {
                this.targetOptions.set([
                    ...targets.repositories.map((row) => ({ label: `Repository — ${row.label}`, value: `repository:${row.id}` })),
                    ...targets.containers.map((row) => ({ label: `Container — ${row.label}`, value: `container:${row.id}` }))
                ]);
            },
            // Silent: without the list the field stays empty and the key covers every target.
            // That is degraded, not broken — no reason to alarm anybody.
            error: () => this.targetOptions.set([])
        });
    }

    reload(preserveError = false): void {
        this.loading.set(true);
        this.api.apiKeys().subscribe({
            next: (keys) => {
                this.keys.set(keys);
                if (!preserveError) this.error.set(null);
                this.loading.set(false);
            },
            error: () => {
                this.error.set('Could not load the key list.');
                this.loading.set(false);
            }
        });
    }

    scopeLabel(scope: string): string {
        return SCOPES.find((entry) => entry.value === scope)?.label ?? scope;
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
        this.api
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
                    this.formError.set(messageOf(response, 'Could not issue this key.'));
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
        this.api.deleteApiKey(key.id).subscribe({
            next: () => {
                this.saving.set(false);
                this.deleteVisible.set(false);
                this.reload();
            },
            error: (response) => {
                this.saving.set(false);
                this.deleteVisible.set(false);
                this.error.set(messageOf(response, 'The revocation failed.'));
                this.reload(true);
            }
        });
    }
}
