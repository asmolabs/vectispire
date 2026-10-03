import type { I18nService } from '../core/i18n/i18n.service';
import { keyFor } from '../core/i18n/literal-keys';

/**
 * The triage statuses the bundle names. The document types `triageStatus` as a plain string; the
 * five the server writes today are `TRIAGE_STATUSES` in `core/testing/contract.ts`, and `accepted`
 * and `false_positive` are older decisions still found in the history.
 */
export type TriageStatus =
    'under_review' | 'pending_approval' | 'affected' | 'not_affected' | 'fixed' | 'accepted' | 'false_positive';

/**
 * A triage status in words, **written once with literal keys** (decision 0019). The issue page and
 * the history each kept a set of the known statuses and built `issues.triage_status.${status}` from
 * it — two copies of one list, and a key the i18n check could not read.
 */
export const TRIAGE_STATUS_KEYS = {
    under_review: 'issues.triage_status.under_review',
    pending_approval: 'issues.triage_status.pending_approval',
    affected: 'issues.triage_status.affected',
    not_affected: 'issues.triage_status.not_affected',
    fixed: 'issues.triage_status.fixed',
    accepted: 'issues.triage_status.accepted',
    false_positive: 'issues.triage_status.false_positive'
} as const satisfies Record<TriageStatus, string>;

/** Open set: a status this client does not know is shown as sent rather than hidden. */
export function triageStatusLabel(i18n: I18nService, status: string): string {
    const key = keyFor(TRIAGE_STATUS_KEYS, status);
    return key ? i18n.t(key) : status;
}
