import { CommonModule } from '@angular/common';
import { Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { SelectModule } from '@openng/optimus-ui/select';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import { AuditApi } from '../../core/api/audit.api';
import type { AuditEntry, AuditVerification } from '../../core/api.models';

/** Operation types, in words — keys rather than text, resolved at render time so a language
 *  switch relabels them. Open table: an unknown type is shown raw rather than hidden —
 *  the log must show what it holds, not what somebody expected it to hold. */
const OPERATION_KEYS: Record<string, string> = {
    SETTING_UPDATED: 'audit_log.operations.setting_updated',
    ACCESS_DENIED: 'audit_log.operations.access_denied',
    LOGIN: 'audit_log.operations.login',
    LOGOUT: 'audit_log.operations.logout',
    TRIAGE: 'audit_log.operations.triage',
    SCAN_TRIGGERED: 'audit_log.operations.scan_triggered',
    POLICY_UPDATED: 'audit_log.operations.policy_updated',
    TEAM_UPDATED: 'audit_log.operations.team_updated',
    TEAM_ACCESS_CHANGED: 'audit_log.operations.team_access_changed'
};

const PAGE_SIZE = 50;

import { I18nService } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { LatestRequest } from '@/app/core/latest-request';

@Component({
    selector: 'app-audit-log',
    standalone: true,
    imports: [CommonModule, FormsModule, ButtonModule, CardModule, InputTextModule, MessageModule, SelectModule, TableModule, TagModule, TranslatePipe],
    templateUrl: './audit-log.html'
})
export class AuditLog {
    private readonly page = new LatestRequest();

    private readonly auditApi = inject(AuditApi);
    private readonly i18n = inject(I18nService);

    readonly entries = signal<AuditEntry[]>([]);
    readonly total = signal(0);
    readonly offset = signal(0);
    readonly loading = signal(true);
    readonly verifying = signal(true);
    readonly verification = signal<AuditVerification | null>(null);
    readonly error = signal<string | null>(null);
    private readonly operationTypes = signal<string[]>([]);
    readonly operationOptions = computed(() => {
        this.i18n.translations();
        return this.operationTypes().map((type) => ({ label: this.operationLabel(type), value: type }));
    });

    filters: { operationType: string | null; userId: string; search: string } = { operationType: null, userId: '', search: '' };

    constructor() {
        this.reload();

        this.auditApi.verifyAuditChain().subscribe({
            next: (result) => {
                this.verification.set(result);
                this.verifying.set(false);
            },
            error: () => {
                this.verifying.set(false);
                // Distinct from a broken chain: not knowing is not knowing that it is broken,
                // and showing "broken" on a network failure would be a lie.
                this.error.set(this.i18n.t('audit_log.error_verify'));
            }
        });

        this.auditApi.auditOperationTypes().subscribe({
            // Checked, not trusted: read inside a computed the template renders, a value that is
            // not a list broke the whole screen — the log included — instead of just the filter.
            next: (types) => this.operationTypes.set(Array.isArray(types) ? types : []),
            error: () => this.operationTypes.set([])
        });
    }

    operationLabel(type: string | null): string {
        if (!type) return '—';
        const key = OPERATION_KEYS[type];
        return key ? this.i18n.t(key) : type;
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
        // Called on every keystroke of the search box: latest wins, or answers land out of order.
        this.page.run(this.auditApi
            .auditLog({
                operation_type: this.filters.operationType ?? undefined,
                user_id: this.filters.userId.trim() || undefined,
                search: this.filters.search.trim() || undefined,
                limit: PAGE_SIZE,
                offset: this.offset()
            }), {
                next: (page) => {
                    this.entries.set(page.items);
                    this.total.set(page.total);
                    this.loading.set(false);
                },
                error: () => {
                    this.error.set(this.i18n.t('audit_log.error_load'));
                    this.loading.set(false);
                }
            });
    }
}
