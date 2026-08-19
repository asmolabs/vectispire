import { CommonModule } from '@angular/common';
import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { SelectModule } from '@openng/optimus-ui/select';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import { ApiService } from '../../core/api.service';
import type { AuditEntry, AuditVerification } from '../../core/api.models';

/** Operation types, in words. Open table: an unknown type is shown raw rather than hidden —
 *  the log must show what it holds, not what somebody expected it to hold. */
const OPERATION_LABELS: Record<string, string> = {
    SETTING_UPDATED: 'Setting changed',
    ACCESS_DENIED: 'Access denied',
    LOGIN: 'Sign in',
    LOGOUT: 'Sign out',
    TRIAGE: 'Triage',
    SCAN_TRIGGERED: 'Scan triggered',
    POLICY_UPDATED: 'Policy changed'
};

const PAGE_SIZE = 50;

@Component({
    selector: 'app-audit-log',
    standalone: true,
    imports: [CommonModule, FormsModule, ButtonModule, CardModule, InputTextModule, MessageModule, SelectModule, TableModule, TagModule],
    template: `
        <div class="mb-4">
            <h1 class="text-2xl font-semibold m-0">Audit log</h1>
            <p class="text-muted-color mt-1 mb-0">The sensitive operations, and the state of the chain that protects them.</p>
        </div>

        <!--
            The chaining has existed from the start and could only be verified by a script. A
            log whose integrity nobody ever looks at mostly protects the conscience of whoever
            wrote it: the result has to be visible without effort.
        -->
        @if (verification(); as result) {
            @if (result.intact) {
                <p-message severity="success" [closable]="false" styleClass="mb-4 w-full">
                    Chain intact — {{ result.verified }} entry(ies) verified
                    @if (result.unverifiable > 0) {
                        , {{ result.unverifiable }} predating the chaining
                    }
                    .
                </p-message>
            } @else {
                <p-message severity="error" [closable]="false" styleClass="mb-4 w-full">
                    <strong>Chain broken.</strong> {{ result.broken }}
                </p-message>
            }
        } @else if (verifying()) {
            <p-message severity="secondary" [closable]="false" styleClass="mb-4 w-full">Verifying the chain…</p-message>
        }

        @if (error(); as message) {
            <p-message severity="error" [closable]="false" styleClass="mb-4 w-full">{{ message }}</p-message>
        }

        <p-card>
            <div class="flex flex-wrap gap-3 mb-4 items-end">
                <div class="flex flex-col gap-2">
                    <label for="type" class="font-medium text-sm">Operation</label>
                    <p-select id="type" [options]="operationOptions()" optionLabel="label" optionValue="value"
                              [(ngModel)]="filters.operationType" (ngModelChange)="search()" [showClear]="true"
                              placeholder="All" [style]="{ minWidth: '14rem' }" />
                </div>
                <div class="flex flex-col gap-2">
                    <label for="user" class="font-medium text-sm">User</label>
                    <input pInputText id="user" [(ngModel)]="filters.userId" (keyup.enter)="search()" placeholder="Any" />
                </div>
                <div class="flex flex-col gap-2 flex-1" style="min-width: 16rem">
                    <label for="q" class="font-medium text-sm">Description contient</label>
                    <input pInputText id="q" [(ngModel)]="filters.search" (keyup.enter)="search()" class="w-full" />
                </div>
                <p-button label="Filtrer" icon="pi pi-search" (onClick)="search()" />
            </div>

            <p-table [value]="entries()" [loading]="loading()" dataKey="id" styleClass="p-datatable-sm">
                <ng-template #header>
                    <tr>
                        <th style="width: 11rem">Timestamp</th>
                        <th style="width: 12rem">Operation</th>
                        <th>Description</th>
                        <th style="width: 9rem">User</th>
                        <th style="width: 9rem">IP address</th>
                    </tr>
                </ng-template>
                <ng-template #body let-entry>
                    <tr>
                        <td class="whitespace-nowrap text-sm">{{ entry.timestamp | date: 'dd/MM/yyyy HH:mm:ss' }}</td>
                        <td><p-tag [value]="operationLabel(entry.operationType)" severity="secondary" /></td>
                        <td>{{ entry.description }}</td>
                        <td>{{ entry.userId || '—' }}</td>
                        <td class="font-mono text-sm">{{ entry.ipAddress || '—' }}</td>
                    </tr>
                </ng-template>
                <ng-template #emptymessage>
                    <tr><td colspan="5" class="text-center text-muted-color py-6">No entry.</td></tr>
                </ng-template>
            </p-table>

            @if (total() > 0) {
                <div class="flex items-center justify-between mt-4">
                    <span class="text-sm text-muted-color">
                        {{ offset() + 1 }}–{{ shownTo() }} of {{ total() }}
                    </span>
                    <div class="flex gap-2">
                        <p-button label="Previous" icon="pi pi-chevron-left" [text]="true" [disabled]="offset() === 0" (onClick)="previous()" />
                        <p-button label="Next" icon="pi pi-chevron-right" iconPos="right" [text]="true"
                                  [disabled]="shownTo() >= total()" (onClick)="next()" />
                    </div>
                </div>
            }
        </p-card>
    `
})
export class AuditLog {
    private readonly api = inject(ApiService);

    readonly entries = signal<AuditEntry[]>([]);
    readonly total = signal(0);
    readonly offset = signal(0);
    readonly loading = signal(true);
    readonly verifying = signal(true);
    readonly verification = signal<AuditVerification | null>(null);
    readonly error = signal<string | null>(null);
    readonly operationOptions = signal<{ label: string; value: string }[]>([]);

    filters: { operationType: string | null; userId: string; search: string } = { operationType: null, userId: '', search: '' };

    constructor() {
        this.reload();

        this.api.verifyAuditChain().subscribe({
            next: (result) => {
                this.verification.set(result);
                this.verifying.set(false);
            },
            error: () => {
                this.verifying.set(false);
                // Distinct from a broken chain: not knowing is not knowing that it is broken,
                // and showing "broken" on a network failure would be a lie.
                this.error.set('Verifying the chain did not complete. Its state is unknown, which is not the same thing as broken.');
            }
        });

        this.api.auditOperationTypes().subscribe({
            next: (types) => this.operationOptions.set(types.map((type) => ({ label: this.operationLabel(type), value: type }))),
            error: () => this.operationOptions.set([])
        });
    }

    operationLabel(type: string | null): string {
        if (!type) return '—';
        return OPERATION_LABELS[type] ?? type;
    }

    shownTo(): number {
        return Math.min(this.offset() + this.entries().length, this.total());
    }

    search(): void {
        this.offset.set(0);
        this.reload();
    }

    previous(): void {
        this.offset.set(Math.max(0, this.offset() - PAGE_SIZE));
        this.reload();
    }

    next(): void {
        this.offset.set(this.offset() + PAGE_SIZE);
        this.reload();
    }

    private reload(): void {
        this.loading.set(true);
        this.api
            .auditLog({
                operation_type: this.filters.operationType ?? undefined,
                user_id: this.filters.userId.trim() || undefined,
                search: this.filters.search.trim() || undefined,
                limit: PAGE_SIZE,
                offset: this.offset()
            })
            .subscribe({
                next: (page) => {
                    this.entries.set(page.items);
                    this.total.set(page.total);
                    this.loading.set(false);
                },
                error: () => {
                    this.error.set('Could not load the log.');
                    this.loading.set(false);
                }
            });
    }
}
