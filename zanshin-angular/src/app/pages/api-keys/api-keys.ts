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
    template: `
        <div class="mb-4 flex items-start justify-between gap-4">
            <div>
                <h1 class="text-2xl font-semibold m-0">API keys</h1>
                <p class="text-muted-color mt-1 mb-0">The keys that authenticate automated calls.</p>
            </div>
            <p-button label="Issue a key" icon="pi pi-plus" (onClick)="openForm()" />
        </div>

        @if (error(); as message) {
            <p-message severity="error" [closable]="false" styleClass="mb-4 w-full">{{ message }}</p-message>
        }

        <p-card>
            <p-table [value]="keys()" [loading]="loading()" dataKey="id" styleClass="p-datatable-sm">
                <ng-template #header>
                    <tr>
                        <th>Name</th>
                        <th>Prefix</th>
                        <th>Scopes</th>
                        <th>Target</th>
                        <th>Last used</th>
                        <th>Expiration</th>
                        <th class="w-1"></th>
                    </tr>
                </ng-template>
                <ng-template #body let-key>
                    <tr>
                        <td class="font-medium">{{ key.name }}</td>
                        <td class="font-mono text-sm whitespace-nowrap">{{ key.prefix }}…</td>
                        <td>
                            <div class="flex flex-wrap gap-1">
                                @for (scope of key.scopes; track scope) {
                                    <!-- "agent" in red: it grants the right to run scans, and reads
                                         too much like "scan". -->
                                    <p-tag [value]="scopeLabel(scope)" [severity]="scope === 'agent' ? 'danger' : 'secondary'" />
                                }
                            </div>
                        </td>
                        <td>
                            @if (key.targetLabel) {
                                <span class="text-sm">{{ key.targetLabel }}</span>
                            } @else {
                                <span class="text-muted-color">All</span>
                            }
                        </td>
                        <td>
                            @if (key.lastUsedAt) {
                                {{ key.lastUsedAt | date: 'dd/MM/yyyy HH:mm' }}
                            } @else {
                                <!-- Never used is not nothing: it is often a key issued for a use
                                     that never happened, and therefore one to revoke. -->
                                <span class="text-muted-color">Never</span>
                            }
                        </td>
                        <td>
                            @if (key.isExpired) {
                                <p-tag value="Expired" severity="danger" />
                            } @else if (key.expiresAt) {
                                {{ key.expiresAt | date: 'dd/MM/yyyy' }}
                            } @else {
                                <span class="text-muted-color">No limit</span>
                            }
                        </td>
                        <td class="text-right">
                            <p-button icon="pi pi-trash" severity="danger" [text]="true" [rounded]="true"
                                      [ariaLabel]="'Revoke ' + key.name" (onClick)="askDelete(key)" />
                        </td>
                    </tr>
                </ng-template>
                <ng-template #emptymessage>
                    <tr><td colspan="7" class="text-center text-muted-color py-6">No key issued.</td></tr>
                </ng-template>
            </p-table>
        </p-card>

        <p-dialog header="Issue an API key" [(visible)]="formVisible" [modal]="true" [style]="{ width: '36rem' }">
            <div class="flex flex-col gap-4">
                <div class="flex flex-col gap-2">
                    <label for="name" class="font-medium">Nom</label>
                    <input pInputText id="name" [(ngModel)]="form.name" placeholder="Integration pipeline" />
                    <small class="text-muted-color">What will make it possible to know which one to revoke.</small>
                </div>

                <div class="flex flex-col gap-2">
                    <span class="font-medium">Scopes</span>
                    @for (scope of scopes; track scope.value) {
                        <div class="flex items-start gap-2">
                            <p-checkbox [inputId]="scope.value" [binary]="true" [ngModel]="form.scopes.includes(scope.value)"
                                        (ngModelChange)="toggleScope(scope.value, $event)" />
                            <label [for]="scope.value" class="cursor-pointer">
                                <span [class.text-red-500]="scope.value === 'agent'">{{ scope.label }}</span>
                                <span class="block text-sm text-muted-color">{{ scope.hint }}</span>
                            </label>
                        </div>
                    }
                </div>

                <div class="flex flex-col gap-2">
                    <label for="target" class="font-medium">Restrict to one target <span class="text-muted-color font-normal">(optional)</span></label>
                    <p-select id="target" [options]="targetOptions()" optionLabel="label" optionValue="value"
                              [(ngModel)]="form.target" [showClear]="true" placeholder="All targets" styleClass="w-full" />
                </div>

                <div class="flex flex-col gap-2">
                    <label for="lifetime" class="font-medium">Expires in <span class="text-muted-color font-normal">(optional)</span></label>
                    <p-inputnumber inputId="lifetime" [(ngModel)]="form.expiresInDays" [min]="1" [max]="3650" suffix=" days" styleClass="w-full" />
                </div>

                @if (formError(); as message) {
                    <p-message severity="error" [closable]="false">{{ message }}</p-message>
                }
            </div>
            <ng-template #footer>
                <p-button label="Cancel" [text]="true" (onClick)="formVisible.set(false)" />
                <p-button label="Issue" [loading]="saving()" (onClick)="submit()" />
            </ng-template>
        </p-dialog>

        <!-- The only time the value exists. Closing this window loses it for good, and that is
             said before, not after. -->
        <p-dialog header="Key issued" [(visible)]="secretVisible" [modal]="true" [closable]="false" [style]="{ width: '36rem' }">
            <p-message severity="warn" [closable]="false" styleClass="mb-4 w-full">
                Copy it now: it is stored only as a hash and cannot be shown again.
            </p-message>
            <div class="font-mono text-sm p-3 border rounded break-all select-all" style="border-color: var(--surface-border)">{{ issuedSecret() }}</div>
            <ng-template #footer>
                <p-button label="I have copied the key" (onClick)="dismissSecret()" />
            </ng-template>
        </p-dialog>

        <p-dialog header="Revoke this key?" [(visible)]="deleteVisible" [modal]="true" [style]="{ width: '30rem' }">
            @if (pendingDelete(); as key) {
                <p class="m-0">
                    <span class="font-medium">{{ key.name }}</span> will stop working immediately. Every call
                    that uses it will fail. This is permanent.
                </p>
            }
            <ng-template #footer>
                <p-button label="Cancel" [text]="true" (onClick)="deleteVisible.set(false)" />
                <p-button label="Revoke" severity="danger" [loading]="saving()" (onClick)="confirmDelete()" />
            </ng-template>
        </p-dialog>
    `
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
