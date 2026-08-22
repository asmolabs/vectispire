import { CommonModule } from '@angular/common';
import { Component, input } from '@angular/core';
import { TagModule } from '@openng/optimus-ui/tag';
import type { LastScan } from '../core/api.models';

/**
 * The state of a target's last scan, repository or container alike.
 *
 * Extracted because the distinction it carries is too easy to lose when copied:
 * **"never scanned" is not "no problem"**, it is an absence of observation. A screen that
 * renders an empty cell in that case lies by omission.
 */
/**
 * The keys are the database's, not the ones you would expect.
 *
 * `pending` and `scanning` — not `queued` and `running` — because those are the values the
 * column holds. The first version used the expected names and the screen displayed a raw
 * "pending": the closed table had done its job by showing the unknown value rather than
 * hiding it behind a reassuring label, but it translated nothing. Seen on screen, not in
 * review.
 */
import { inject } from '@angular/core';
import { TranslatePipe } from '../core/i18n/translate.pipe';
import { I18nService } from '../core/i18n/i18n.service';

const STATUS_KEYS: Record<string, { key: string; severity: 'success' | 'warn' | 'danger' | 'info' }> = {
    pending: { key: 'scans.status_queued', severity: 'info' },
    scanning: { key: 'scans.status_running', severity: 'info' },
    completed: { key: 'scans.status_completed', severity: 'success' },
    failed: { key: 'scans.status_failed', severity: 'danger' },
    cancelled: { key: 'scans.status_cancelled', severity: 'warn' }
};

@Component({
    selector: 'app-last-scan',
    standalone: true,
    imports: [CommonModule, TagModule, TranslatePipe],
    templateUrl: './last-scan.html'
})
export class LastScanTag {
    private readonly i18n = inject(I18nService);
    readonly scan = input.required<LastScan | null>();

    label(status: string): string {
        const item = STATUS_KEYS[status];
        return item ? this.i18n.t(item.key) : status;
    }

    severity(status: string): 'success' | 'warn' | 'danger' | 'info' {
        return STATUS_KEYS[status]?.severity ?? 'info';
    }
}
