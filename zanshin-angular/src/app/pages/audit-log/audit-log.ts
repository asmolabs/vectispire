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
    templateUrl: './audit-log.html'
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
