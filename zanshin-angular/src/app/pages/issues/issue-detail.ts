import { CommonModule } from '@angular/common';
import { Component, inject, input, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { CardModule } from '@openng/optimus-ui/card';
import { MessageModule } from '@openng/optimus-ui/message';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import { ApiService } from '../../core/api.service';
import type { IssueDetail } from '../../core/api.models';

const SEVERITY_SEVERITY: Record<string, 'danger' | 'warn' | 'secondary'> = {
    critical: 'danger',
    high: 'danger',
    medium: 'warn',
    low: 'secondary',
    negligible: 'secondary',
    unknown: 'secondary'
};

const TRIAGE_LABELS: Record<string, string> = {
    under_review: 'Under review',
    pending_approval: 'Pending approval',
    not_affected: 'Not affected',
    affected: 'Affected',
    fixed: 'Fixed',
    accepted: 'Risk accepted',
    false_positive: 'False positive'
};

/**
 * One issue, with what a row in the backlog cannot carry.
 *
 * The list already sends every column of an issue; this page exists for the two things that need
 * a query of their own — **where it was seen**, scan by scan with the project version each one
 * read, and **what was decided**, every triage transition with its author and justification.
 *
 * Those two answer the questions a row provokes and cannot settle: "is this still there in the
 * release we shipped" and "why is this dismissed".
 */
import { TranslatePipe } from '../../core/i18n/translate.pipe';

@Component({
    selector: 'app-issue-detail',
    standalone: true,
    imports: [CommonModule, RouterLink, CardModule, TableModule, TagModule, MessageModule, TranslatePipe],
    templateUrl: './issue-detail.html'
})
export class IssueDetailPage {
    private readonly api = inject(ApiService);

    readonly id = input.required<string>();
    readonly issue = signal<IssueDetail | null>(null);
    readonly error = signal<string | null>(null);

    constructor() {
        queueMicrotask(() => {
            this.api.issue(Number(this.id())).subscribe({
                next: (detail) => this.issue.set(detail),
                error: () => this.error.set('This issue could not be loaded.')
            });
        });
    }

    severityOf(severity: string | null): 'danger' | 'warn' | 'secondary' {
        return SEVERITY_SEVERITY[severity ?? 'unknown'] ?? 'secondary';
    }

    triageLabel(status: string | null): string {
        return status ? (TRIAGE_LABELS[status] ?? status) : '—';
    }

    typeLabel(type: string): string {
        return type === 'sast' ? 'Vulnerable code' : type;
    }
}
