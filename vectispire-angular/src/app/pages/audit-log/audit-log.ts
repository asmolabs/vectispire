import { CommonModule } from '@angular/common';
import { Component, computed, inject, signal, ChangeDetectionStrategy } from '@angular/core';
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
    // One line per `AuditOperation`, in its order — `AuditOperationLabelsTest` (vectispire-core)
    // fails on one missing here or in either dictionary.
    LOGIN_SUCCESS: 'audit_log.operations.login_success',
    LOGIN_FAILURE: 'audit_log.operations.login_failure',
    LOGIN_BLOCKED: 'audit_log.operations.login_blocked',
    PASSWORD_CHANGED: 'audit_log.operations.password_changed',
    USER_CREATED: 'audit_log.operations.user_created',
    USER_UPDATED: 'audit_log.operations.user_updated',
    USER_PASSWORD_RESET: 'audit_log.operations.user_password_reset',
    USER_DELETED: 'audit_log.operations.user_deleted',
    API_KEY_CREATED: 'audit_log.operations.api_key_created',
    API_KEY_DELETED: 'audit_log.operations.api_key_deleted',
    SETTING_UPDATED: 'audit_log.operations.setting_updated',
    ISSUE_TRIAGED: 'audit_log.operations.issue_triaged',
    SCAN_TRIGGERED: 'audit_log.operations.scan_triggered',
    AI_REVIEW_REQUESTED: 'audit_log.operations.ai_review_requested',
    REPORT_EXPORTED: 'audit_log.operations.report_exported',
    TICKET_CREATED: 'audit_log.operations.ticket_created',
    TICKET_LINKED: 'audit_log.operations.ticket_linked',
    TICKET_CLOSED: 'audit_log.operations.ticket_closed',
    TICKET_SYNCED: 'audit_log.operations.ticket_synced',
    GATE_POLICY_UPDATED: 'audit_log.operations.gate_policy_updated',
    CONTROL_DECLARED: 'audit_log.operations.control_declared',
    CERTIFIED_SCOPE_CHANGED: 'audit_log.operations.certified_scope_changed',
    THREAT_INTEL_SYNCED: 'audit_log.operations.threat_intel_synced',
    TEAM_UPDATED: 'audit_log.operations.team_updated',
    TEAM_ACCESS_CHANGED: 'audit_log.operations.team_access_changed',
    // Decision 0023. A creation and a deletion are recorded under the `_UPDATED` of their kind,
    // as for teams; a filing or a move under its own, because it changes who sees a repository.
    SOLUTION_UPDATED: 'audit_log.operations.solution_updated',
    PROJECT_UPDATED: 'audit_log.operations.project_updated',
    PROJECT_REPOSITORIES_CHANGED: 'audit_log.operations.project_repositories_changed',
    ACCESS_DENIED: 'audit_log.operations.access_denied',
    AGENT_CREDENTIAL_SENT: 'audit_log.operations.agent_credential_sent',
    AGENT_RESULT_SUBMITTED: 'audit_log.operations.agent_result_submitted',
    AGENT_RESULT_REFUSED: 'audit_log.operations.agent_result_refused',
    AGENT_SIGNING_KEY_PINNED: 'audit_log.operations.agent_signing_key_pinned',
    AGENT_SEALING_KEY_ACCEPTED: 'audit_log.operations.agent_sealing_key_accepted',
    AGENT_SEALING_KEY_REFUSED: 'audit_log.operations.agent_sealing_key_refused',
    AGENT_SEALING_KEY_RESET: 'audit_log.operations.agent_sealing_key_reset',
    BADGE_PUBLISHED: 'audit_log.operations.badge_published',
    RULE_SET_UPLOADED: 'audit_log.operations.rule_set_uploaded',
    RULE_SET_ACTIVATED: 'audit_log.operations.rule_set_activated',
    RULE_SET_DEACTIVATED: 'audit_log.operations.rule_set_deactivated',
    AGENT_CREATED: 'audit_log.operations.agent_created',
    AGENT_UPDATED: 'audit_log.operations.agent_updated',
    AGENT_DELETED: 'audit_log.operations.agent_deleted',
    POSTURE_DIGEST_SENT: 'audit_log.operations.posture_digest_sent',
    PLUGIN_REGISTERED: 'audit_log.operations.plugin_registered',
    PLUGIN_UPDATED: 'audit_log.operations.plugin_updated',
    PLUGIN_ENABLED_CHANGED: 'audit_log.operations.plugin_enabled_changed',
    PLUGIN_ACTIVATED: 'audit_log.operations.plugin_activated',
    PLUGIN_DEACTIVATED: 'audit_log.operations.plugin_deactivated',
    SARIF_SOURCE_CHANGED: 'audit_log.operations.sarif_source_changed',
    SARIF_IMPORTED: 'audit_log.operations.sarif_imported',
    SARIF_IMPORT_REFUSED: 'audit_log.operations.sarif_import_refused',
    // Named by no `AuditOperation`: kept so that an entry recorded under one still reads.
    LOGIN: 'audit_log.operations.login',
    LOGOUT: 'audit_log.operations.logout',
    TRIAGE: 'audit_log.operations.triage',
    POLICY_UPDATED: 'audit_log.operations.policy_updated'
};

const PAGE_SIZE = 50;

import { I18nService } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { LatestRequest } from '@/app/core/latest-request';

@Component({
    selector: 'app-audit-log',
    standalone: true,
    imports: [
        CommonModule,
        FormsModule,
        ButtonModule,
        CardModule,
        InputTextModule,
        MessageModule,
        SelectModule,
        TableModule,
        TagModule,
        TranslatePipe
    ],
    changeDetection: ChangeDetectionStrategy.Eager,
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

    filters: { operationType: string | null; userId: string; search: string } = {
        operationType: null,
        userId: '',
        search: ''
    };

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
        this.page.run(
            this.auditApi.auditLog({
                operation_type: this.filters.operationType ?? undefined,
                user_id: this.filters.userId.trim() || undefined,
                search: this.filters.search.trim() || undefined,
                limit: PAGE_SIZE,
                offset: this.offset()
            }),
            {
                next: (page) => {
                    this.entries.set(page.items);
                    this.total.set(page.total);
                    this.loading.set(false);
                },
                error: () => {
                    this.error.set(this.i18n.t('audit_log.error_load'));
                    this.loading.set(false);
                }
            }
        );
    }
}
