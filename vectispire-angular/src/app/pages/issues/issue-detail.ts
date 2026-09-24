import { CommonModule } from '@angular/common';
import { Component, computed, inject, input, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import { messageOf } from '../../core/api-error';
import { IssuesApi } from '../../core/api/issues.api';
import { SessionStore } from '../../core/session.store';
import { I18nService } from '../../core/i18n/i18n.service';
import type { IssueDetail } from '../../core/api.models';

const SEVERITY_SEVERITY: Record<string, 'danger' | 'warn' | 'secondary'> = {
    critical: 'danger',
    high: 'danger',
    medium: 'warn',
    low: 'secondary',
    negligible: 'secondary',
    unknown: 'secondary'
};

/** Triage statuses the bundle names, under `issues.triage_status.*`. Open set: an unknown value
 *  is shown raw rather than hidden. */
const TRIAGE_STATUSES = new Set(['under_review', 'pending_approval', 'not_affected', 'affected', 'fixed', 'accepted', 'false_positive']);

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
    imports: [CommonModule, FormsModule, RouterLink, ButtonModule, CardModule, InputTextModule, TableModule, TagModule, MessageModule, TranslatePipe],
    templateUrl: './issue-detail.html'
})
export class IssueDetailPage {
    private readonly issuesApi = inject(IssuesApi);
    private readonly session = inject(SessionStore);
    private readonly i18n = inject(I18nService);

    readonly id = input.required<string>();
    readonly issue = signal<IssueDetail | null>(null);
    readonly error = signal<string | null>(null);

    /**
     * The ticket tracking this finding.
     *
     * <p><b>The sweep opened tickets, and nobody else could attach one.</b> It deals only with
     * findings that breach the gate, using the globally configured tracker: a team tracking this one
     * in `SEC-1234` had no way of saying so, and the closing webhook — which finds the finding *by
     * its reference* — could therefore not recognise it.
     *
     * <p>The form is offered only to accounts that can act: showing it to an auditor would be
     * offering a door the server closes.
     */
    readonly canAttach = computed(() => this.session.canCauseEffects());
    readonly editingTicket = signal(false);
    readonly attaching = signal(false);
    readonly ticketError = signal<string | null>(null);

    ticketReference = '';
    ticketUrl = '';

    constructor() {
        queueMicrotask(() => {
            this.issuesApi.issue(Number(this.id())).subscribe({
                next: (detail) => this.issue.set(detail),
                error: () => this.error.set(this.i18n.t('issues.detail_load_failed'))
            });
        });
    }

    severityOf(severity: string | null): 'danger' | 'warn' | 'secondary' {
        return SEVERITY_SEVERITY[severity ?? 'unknown'] ?? 'secondary';
    }

    triageLabel(status: string | null): string {
        return status ? (TRIAGE_STATUSES.has(status) ? this.i18n.t(`issues.triage_status.${status}`) : status) : '—';
    }

    typeLabel(type: string): string {
        return type === 'sast' ? this.i18n.t('issues.types.sast') : type;
    }

    /** Opens the form, pre-filled with what is already attached. */
    editTicket(): void {
        const detail = this.issue();
        this.ticketReference = detail?.ticketRef ?? '';
        this.ticketUrl = detail?.ticketUrl ?? '';
        this.ticketError.set(null);
        this.editingTicket.set(true);
    }

    /**
     * Attaches, or corrects.
     *
     * <p>An empty reference is not sent: the server refuses it, and rightly — a field emptied by
     * mistake would make the finding invisible to the webhook *and* reopen the door to a second
     * ticket from the sweep, with nothing saying so. The screen therefore does not offer the move
     * rather than having it refused.
     */
    saveTicket(): void {
        const detail = this.issue();
        const reference = this.ticketReference.trim();
        if (!detail || !reference) return;

        this.attaching.set(true);
        this.ticketError.set(null);
        this.issuesApi.attachTicket(detail.id, reference, this.ticketUrl.trim() || null).subscribe({
            next: (updated) => {
                this.attaching.set(false);
                this.editingTicket.set(false);
                // The finding the server returns carries the reference as it was written — trimmed,
                // possibly refused — and that is the one to show.
                this.issue.set({ ...detail, ticketRef: updated.ticketRef, ticketUrl: updated.ticketUrl });
            },
            error: (response) => {
                this.attaching.set(false);
                this.ticketError.set(messageOf(response, this.i18n.t('issues.ticket_attach_failed')));
            }
        });
    }
}
