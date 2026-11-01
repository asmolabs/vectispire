import { Pipe, PipeTransform } from '@angular/core';

/** The longest review delay the server accepts, in days — ten years. */
export const MAX_REVIEW_DAYS = 3650;

/**
 * Whether a triage draft may be sent: a risk accepted needs a review date the server accepts, and
 * "not affected" — or a request for it — a justification. Preventing the submission beats explaining
 * a refusal afterwards.
 */
export function triageSubmittable(status: string, justification: string | null, days: number | null): boolean {
    if (status === 'will_not_fix') {
        return days !== null && Number.isInteger(days) && days >= 1 && days <= MAX_REVIEW_DAYS;
    }
    return (status !== 'not_affected' && status !== 'pending_approval') || !!justification;
}

/**
 * `triageStatus | triageSubmittable: triageJustification : triageExpiresInDays` — the dialog's draft is
 * plain fields its callers and specs write directly, so a computed reading them would freeze; a pure
 * pipe given all three is called again whenever one of them changes, and never otherwise.
 */
@Pipe({ name: 'triageSubmittable' })
export class TriageSubmittablePipe implements PipeTransform {
    transform(status: string, justification: string | null, days: number | null): boolean {
        return triageSubmittable(status, justification, days);
    }
}
