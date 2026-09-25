import { CommonModule } from '@angular/common';
import { Component, computed, inject, signal, ChangeDetectionStrategy } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from '@openng/optimus-ui/button';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { TagModule } from '@openng/optimus-ui/tag';
import { messageOf } from '@/app/core/api-error';
import { IssuesApi } from '@/app/core/api/issues.api';
import { I18nService } from '@/app/core/i18n/i18n.service';
import { SessionStore } from '@/app/core/session.store';
import { TranslatePipe } from '@/app/core/i18n/translate.pipe';
import type { ExceptionEntry, ExceptionsRegister, ReviewOutcome } from '@/app/core/api.models';

/**
 * What somebody decided not to fix, and on what conditions.
 *
 * **This is the question an assessor asks first and no dashboard answers.** Every other screen
 * describes what the estate contains; this one describes what has been waived — and a green
 * backlog means two opposite things depending on which of the two produced it.
 *
 * **Two numbers carry the screen, and they are not the acceptances in force.** The lapsed ones —
 * granted for a period, the period has passed, nobody reopened them — and the never-reviewed. The
 * second is the one that did not exist: an acceptance confirmed every quarter and an acceptance
 * nobody has opened since January read identically.
 *
 * Reviewing is reserved to the security lead, as granting is. Confirming is the action that counts
 * and changes nothing: it is what turns "nobody looked" into a dated fact.
 */
@Component({
    selector: 'zs-exceptions',
    standalone: true,
    imports: [
        CommonModule,
        FormsModule,
        ButtonModule,
        DialogModule,
        InputTextModule,
        MessageModule,
        TagModule,
        TranslatePipe
    ],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './exceptions.html'
})
export class Exceptions {
    private readonly issuesApi = inject(IssuesApi);
    private readonly session = inject(SessionStore);
    private readonly i18n = inject(I18nService);

    readonly register = signal<ExceptionsRegister | null>(null);
    readonly error = signal<string | null>(null);
    readonly busy = signal(false);

    /**
     * The rows already loaded, accumulated page by page.
     *
     * <p><b>The counters are derived from them rather than taken from the server.</b> The server
     * counts what it returned on *this* page; showing "23 acceptances in force" above a page of two
     * would be a number describing neither the page nor the register. These describe what the
     * reader has in front of them, and the "load more" button says there are more.
     */
    readonly loaded = signal<ExceptionEntry[]>([]);

    readonly granted = computed(() => this.loaded().filter((entry) => entry.decision === 'not_affected').length);
    readonly awaiting = computed(() => this.loaded().filter((entry) => entry.decision === 'pending_approval').length);
    readonly lapsed = computed(() => this.loaded().filter((entry) => entry.lapsed).length);
    readonly neverReviewed = computed(() => this.loaded().filter((entry) => entry.last_reviewed_at === null).length);

    /**
     * There are rows left to ask for.
     *
     * <p><b>A cursor can arrive with an empty page, and that is intended.</b> Visibility is applied
     * after the read: a whole window can belong to other people only. Hiding the button because the
     * page is empty would make the restricted reader stop just before their own rows.
     */
    readonly hasMore = computed(() => this.register()?.next_cursor != null);

    /**
     * The colour follows the meaning, not the metric.
     *
     * <p><b>"0 lapsed" in red was good news painted as an alarm.</b> A table where good news is red
     * teaches people to ignore red, and it is then the red that matters that becomes invisible —
     * the same reasoning as the coverage banner, applied to a number rather than to a warning.
     */
    alarming(count: number, tone: 'danger' | 'warn'): string {
        if (count === 0) {
            return 'text-emerald-700';
        }
        return tone === 'danger' ? 'text-red-700' : 'text-orange-700';
    }

    /** The card's border goes with the alarm, for the same reason. */
    rail(count: number, tone: 'danger' | 'warn'): string {
        if (count === 0) {
            return 'border-emerald-500';
        }
        return tone === 'danger' ? 'border-red-500' : 'border-orange-400';
    }

    /** La ligne en cours de revue, et ce que le formulaire porte. */
    readonly reviewing = signal<ExceptionEntry | null>(null);
    outcome: ReviewOutcome = 'CONFIRMED';
    comment = '';
    newExpiry = '';

    readonly canReview = computed(() => this.session.isSecurityLead());

    constructor() {
        this.load();
    }

    load(): void {
        this.fetch(null);
    }

    more(): void {
        const cursor = this.register()?.next_cursor;
        if (cursor) {
            this.fetch(cursor);
        }
    }

    private fetch(cursor: string | null): void {
        this.issuesApi.exceptionsRegister(200, cursor).subscribe({
            next: (data) => {
                this.register.set(data);
                this.loaded.update((rows) => (cursor ? [...rows, ...data.entries] : data.entries));
            },
            error: (failure) => this.error.set(messageOf(failure, this.i18n.t('exceptions.load_failed')))
        });
    }

    openReview(entry: ExceptionEntry): void {
        this.outcome = 'CONFIRMED';
        this.comment = '';
        this.newExpiry = '';
        this.error.set(null);
        this.reviewing.set(entry);
    }

    /**
     * Extending with no date is refused by the server; the button is disabled here too.
     *
     * Letting the request go in order to show its error would work, and would make an error message
     * carry what a disabled button says without noise.
     */
    readonly submittable = computed(() => !this.busy());

    incomplete(): boolean {
        return this.outcome === 'EXTENDED' && !this.newExpiry;
    }

    submitReview(): void {
        const entry = this.reviewing();
        if (!entry || this.incomplete()) {
            return;
        }
        this.busy.set(true);
        this.error.set(null);

        this.issuesApi
            .reviewException(
                entry.issue_id,
                this.outcome,
                this.comment.trim() || null,
                this.outcome === 'EXTENDED' ? new Date(this.newExpiry).toISOString() : null
            )
            .subscribe({
                next: (data) => {
                    // **Read again from the beginning rather than merged.** A revocation removes
                    // the row from the register: merging it into what is already loaded would leave
                    // in place an exception that is no longer one, which this register must never
                    // do.
                    this.register.set(data);
                    this.loaded.set(data.entries);
                    this.reviewing.set(null);
                    this.busy.set(false);
                },
                error: (failure) => {
                    this.error.set(messageOf(failure, this.i18n.t('exceptions.review_failed')));
                    this.busy.set(false);
                }
            });
    }

    severityOf(entry: ExceptionEntry): 'danger' | 'warn' | 'info' | 'secondary' {
        switch ((entry.severity ?? '').toLowerCase()) {
            case 'critical':
                return 'danger';
            case 'high':
                return 'warn';
            case 'medium':
                return 'info';
            default:
                return 'secondary';
        }
    }
}
