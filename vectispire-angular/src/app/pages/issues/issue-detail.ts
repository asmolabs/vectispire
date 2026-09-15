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
import { ApiService } from '../../core/api.service';
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
    imports: [CommonModule, FormsModule, RouterLink, ButtonModule, CardModule, InputTextModule, TableModule, TagModule, MessageModule, TranslatePipe],
    templateUrl: './issue-detail.html'
})
export class IssueDetailPage {
    private readonly api = inject(ApiService);
    private readonly session = inject(SessionStore);
    private readonly i18n = inject(I18nService);

    readonly id = input.required<string>();
    readonly issue = signal<IssueDetail | null>(null);
    readonly error = signal<string | null>(null);

    /**
     * Le ticket qui suit ce constat.
     *
     * <p><b>La balayeuse ouvrait des tickets, et personne d'autre ne pouvait en rattacher un.</b>
     * Elle ne s'occupe que des constats qui violent la barrière, avec le traqueur configuré
     * globalement : une équipe qui suit celui-ci dans `SEC-1234` n'avait aucun moyen de le dire,
     * et le webhook de fermeture — qui retrouve le constat *par sa référence* — ne pouvait donc
     * pas la reconnaître.
     *
     * <p>Le formulaire n'est offert qu'aux comptes qui peuvent agir : le montrer à un auditeur
     * serait offrir une porte que le serveur ferme.
     */
    readonly canAttach = computed(() => this.session.canCauseEffects());
    readonly editingTicket = signal(false);
    readonly attaching = signal(false);
    readonly ticketError = signal<string | null>(null);

    ticketReference = '';
    ticketUrl = '';

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

    /** Ouvre le formulaire, prérempli de ce qui est déjà rattaché. */
    editTicket(): void {
        const detail = this.issue();
        this.ticketReference = detail?.ticketRef ?? '';
        this.ticketUrl = detail?.ticketUrl ?? '';
        this.ticketError.set(null);
        this.editingTicket.set(true);
    }

    /**
     * Rattache, ou corrige.
     *
     * <p>Une référence vide n'est pas envoyée : le serveur la refuse, et il a raison — un champ
     * vidé par mégarde rendrait le constat invisible au webhook *et* rouvrirait la porte à un
     * second ticket de la balayeuse, sans que rien ne le dise. L'écran ne propose donc pas le
     * geste plutôt que de le faire refuser.
     */
    saveTicket(): void {
        const detail = this.issue();
        const reference = this.ticketReference.trim();
        if (!detail || !reference) return;

        this.attaching.set(true);
        this.ticketError.set(null);
        this.api.attachTicket(detail.id, reference, this.ticketUrl.trim() || null).subscribe({
            next: (updated) => {
                this.attaching.set(false);
                this.editingTicket.set(false);
                // Le constat rendu par le serveur porte la référence telle qu'elle a été écrite —
                // rognée, éventuellement refusée — et c'est celle-là qu'il faut afficher.
                this.issue.set({ ...detail, ticketRef: updated.ticketRef, ticketUrl: updated.ticketUrl });
            },
            error: (response) => {
                this.attaching.set(false);
                this.ticketError.set(messageOf(response, this.i18n.t('issues.ticket_attach_failed')));
            }
        });
    }
}
