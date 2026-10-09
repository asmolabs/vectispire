import { Pipe, PipeTransform, inject } from '@angular/core';
import { I18nService } from '../core/i18n/i18n.service';
import { keyFor } from '../core/i18n/literal-keys';

/**
 * The keys are the database's, not the ones you would expect.
 *
 * `pending` and `scanning` — not `queued` and `running` — because those are the values the
 * column holds. The first version used the expected names and the screen displayed a raw
 * "pending": the closed table had done its job by showing the unknown value rather than
 * hiding it behind a reassuring label, but it translated nothing. Seen on screen, not in
 * review. The last-scan tag kept this map to itself while the history printed `scan.status` as
 * sent; it is every screen's now. `cancelled` is older than the contract's list and still found.
 */
export const SCAN_STATUS_KEYS = {
    pending: 'scans.status_queued',
    scanning: 'scans.status_running',
    completed: 'scans.status_completed',
    failed: 'scans.status_failed',
    cancelled: 'scans.status_cancelled'
} as const;

export type ScanStatus = keyof typeof SCAN_STATUS_KEYS;

/** A scan's status in words; one the client does not know is shown as sent. */
export function scanStatusLabel(i18n: Pick<I18nService, 't'>, status: string): string {
    const key = keyFor(SCAN_STATUS_KEYS, status);
    return key ? i18n.t(key) : status;
}

/** An issue's state — open or resolved — in the words the backlog's filter already uses. */
export const ISSUE_STATE_KEYS = {
    open: 'issues.states.open',
    resolved: 'issues.states.resolved'
} as const;

export function issueStateLabel(i18n: Pick<I18nService, 't'>, state: string): string {
    const key = keyFor(ISSUE_STATE_KEYS, state);
    return key ? i18n.t(key) : state;
}

@Pipe({
    name: 'scanStatus',
    // Impure like `translate`: the text changes when the language does.
    pure: false
})
export class ScanStatusPipe implements PipeTransform {
    private readonly i18n = inject(I18nService);

    transform(status: string): string {
        return scanStatusLabel(this.i18n, status);
    }
}

@Pipe({
    name: 'issueState',
    pure: false
})
export class IssueStatePipe implements PipeTransform {
    private readonly i18n = inject(I18nService);

    transform(state: string): string {
        return issueStateLabel(this.i18n, state);
    }
}
