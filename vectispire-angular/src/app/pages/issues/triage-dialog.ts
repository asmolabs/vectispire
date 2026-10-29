import { ChangeDetectionStrategy, Component, inject, output, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from '@openng/optimus-ui/button';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { SelectModule } from '@openng/optimus-ui/select';
import { TextareaModule } from '@openng/optimus-ui/textarea';
import { messageOf } from '../../core/api-error';
import { IssuesApi } from '@/app/core/api/issues.api';
import { AiVulnerabilityAdvice, Issue, TriageRequest } from '@/app/core/api.models';
import { I18nService } from '@/app/core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { IssuesPage } from './issues-page';

/** The longest review delay the server accepts, in days — ten years. */
const MAX_REVIEW_DAYS = 3650;

/**
 * The triage status a VEX status suggests.
 *
 * The advisor answers in VEX's vocabulary, and its usual answer — every finding not on the KEV list —
 * is `under_investigation`, which is no triage status: applied as it stood, the dialog's select showed
 * nothing and the server refused the decision for having no status. An investigation is `under_review`
 * here, and anything this screen does not know reads as that too, never as a stronger claim.
 */
export function triageStatusOfVex(status: string | null | undefined): string {
    switch (status) {
        case 'affected':
        case 'not_affected':
        case 'fixed':
            return status;
        default:
            return 'under_review';
    }
}

/**
 * The days from now to a proposed review date, as the dialog's field counts them; null when there is
 * none, or it has passed. Rounded up: the server counts the delay from the approval, so the date granted
 * falls on the proposed day or the one after, never before it.
 */
function reviewDaysLeft(expiresAt: string | null | undefined, now: number = Date.now()): number | null {
    if (!expiresAt) return null;
    const days = Math.ceil((new Date(expiresAt).getTime() - now) / 86_400_000);
    return days >= 1 ? Math.min(days, MAX_REVIEW_DAYS) : null;
}

/**
 * The triage dialog, for one row or the selection.
 *
 * It follows the VEX rules exactly as the API applies them — a justification is **required** for
 * "not affected", without which the statement carries no information and the exported VEX document
 * would be invalid. The field therefore appears only for that status, and the button stays disabled
 * while it is empty: better to prevent the submission than to explain a refusal afterwards. A form,
 * so the fields it needs say so and Enter submits it, through the same check.
 *
 * **The same dialog decides one row or the selection.** Narrow to a CVE (`identifier`), tick the page,
 * decide once — the filters are the grouping, which is why there is no "group by CVE" here and no
 * second route on the server either. Two dialogs would be two places where the VEX rule about a
 * required justification lives, and the second one to be written is the one that forgets it.
 */
@Component({
    selector: 'app-triage-dialog',
    imports: [
        FormsModule,
        ButtonModule,
        DialogModule,
        InputTextModule,
        MessageModule,
        SelectModule,
        TextareaModule,
        TranslatePipe
    ],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './triage-dialog.html'
})
export class TriageDialog {
    private readonly i18n = inject(I18nService);
    private readonly issuesApi = inject(IssuesApi);
    protected readonly page = inject(IssuesPage);

    /** A decision was saved: the list is read again by whoever opened the dialog. */
    readonly decided = output<void>();

    /** A signal, so that opening the dialog from code — not only from a click — redraws it. */
    readonly triageOpen = signal(false);
    triageStatus = 'under_review';
    triageJustification: string | null = null;
    triageComment = '';
    triageExpiresInDays: number | null = null;
    /** What the request being answered asked for, when the dialog opened on one; null otherwise. */
    triageRequested: string | null = null;
    readonly triageError = signal<string | null>(null);
    private triaged: Issue | null = null;
    /** Whether the dialog is deciding on the selection or on one row. */
    private bulk = false;

    /**
     * On a request awaiting approval, the dialog opens on **what was asked**: the status and the review
     * date the requester proposed. It opened on `pending_approval` with the review date emptied, so the
     * approver chose a status of their own and the proposed date was lost — and a tracker's "Won't Fix"
     * could leave granted as "not affected" (decision 0041). The server now refuses a grant that differs;
     * the dialog offers the one it accepts.
     */
    openTriage(issue: Issue): void {
        this.triaged = issue;
        this.bulk = false;
        const pending = issue.triageStatus === 'pending_approval';
        this.triageRequested = pending ? issue.triageRequestedStatus : null;
        this.triageStatus = this.triageRequested ?? issue.triageStatus;
        this.triageJustification = this.triageRequested === 'will_not_fix' ? null : issue.triageJustification;
        this.triageComment = issue.triageComment ?? '';
        this.triageExpiresInDays = pending ? reviewDaysLeft(issue.triageExpiresAt) : null;
        this.triageError.set(null);
        this.triageOpen.set(true);
    }

    /**
     * The same decision on everything ticked.
     *
     * One CVE appears in forty repositories, and "not reachable in our configuration" is one
     * judgement about one context, not forty. Deciding it forty times is how a backlog stops
     * being triaged at all.
     *
     * The fields open on the defaults rather than on any row's current decision: a batch has no
     * single "current" status, and pre-filling from the first tick would present one row's
     * dismissal as the state of all of them.
     */
    openBulkTriage(): void {
        if (this.page.selected().length === 0) return;
        this.triaged = null;
        this.bulk = true;
        this.triageRequested = null;
        this.triageStatus = 'under_review';
        this.triageJustification = null;
        this.triageComment = '';
        this.triageExpiresInDays = null;
        this.triageError.set(null);
        this.triageOpen.set(true);
    }

    /** The advisor's suggestion, applied to the row it was asked about: the decision is still the person's. */
    applySuggestion(issue: Issue, advice: AiVulnerabilityAdvice): void {
        this.openTriage(issue);
        if (advice.vexSuggestion) {
            this.triageStatus = triageStatusOfVex(advice.vexSuggestion.status);
            this.triageJustification = advice.vexSuggestion.justification || null;
            this.triageComment = `${this.i18n.t('issues.ai_suggestion_prefix')} ${advice.vexSuggestion.impactStatement || advice.summaryExplanation}`;
        }
    }

    /** The dialog says how wide the decision is, because "Save" looks identical for one row and
     *  for forty — and one of the two is not undoable row by row. */
    protected triageHeader(): string {
        return this.bulk
            ? this.i18n.t('issues.triage_header_bulk', { count: this.page.selected().length })
            : this.i18n.t('issues.triage_header_single');
    }

    /**
     * A risk accepted is the one decision that cannot go without a review date, and the one that
     * cannot carry a VEX justification: each of the five says why the product is *not* exposed,
     * and this decision says it is (decision 0041). The server refuses both; the dialog says so.
     */
    acceptsRisk(): boolean {
        return this.triageStatus === 'will_not_fix';
    }

    /** The dialog's status, and what a risk accepted takes away: a justification left from a
     *  `not_affected` chosen a moment earlier would otherwise ride along, hidden, and be refused. */
    chooseTriageStatus(status: string): void {
        this.triageStatus = status;
        if (status === 'will_not_fix') this.triageJustification = null;
    }

    /** Preventing the submission beats explaining a refusal afterwards. */
    canSubmitTriage(): boolean {
        if (this.acceptsRisk()) {
            const days = this.triageExpiresInDays;
            return days !== null && Number.isInteger(days) && days >= 1 && days <= MAX_REVIEW_DAYS;
        }
        return (
            (this.triageStatus !== 'not_affected' && this.triageStatus !== 'pending_approval') ||
            !!this.triageJustification
        );
    }

    submitTriage(): void {
        if (!this.canSubmitTriage()) return;
        if (this.bulk) {
            this.submitBulkTriage();
            return;
        }
        if (!this.triaged) return;
        this.issuesApi.triage(this.triaged.id, this.triageBody()).subscribe({
            next: () => {
                this.triageOpen.set(false);
                this.decided.emit();
            },
            error: (response) => this.triageError.set(messageOf(response, this.i18n.t('issues.triage_refused')))
        });
    }

    private triageBody(): TriageRequest {
        return {
            status: this.triageStatus,
            // Null whatever the field holds: the server refuses a justification on a risk accepted.
            justification: this.acceptsRisk() ? null : this.triageJustification,
            comment: this.triageComment || null,
            expires_in_days: this.triageExpiresInDays || null
        };
    }

    private submitBulkTriage(): void {
        const ids = this.page.selected().map((issue) => issue.id);
        if (ids.length === 0) return;
        this.issuesApi.triageMany({ ids, ...this.triageBody() }).subscribe({
            next: () => {
                this.triageOpen.set(false);
                this.decided.emit();
            },
            error: (response) => {
                const refused = this.i18n.t('issues.bulk_triage_refused', { count: ids.length });
                this.triageError.set(
                    (response as { status?: number } | null)?.status === 404
                        ? `${refused} ${this.i18n.t('issues.bulk_triage_not_visible')}`
                        : `${refused} ${messageOf(response, this.i18n.t('issues.triage_refused'))}`
                );
            }
        });
    }
}
