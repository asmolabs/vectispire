import { DatePipe } from '@angular/common';
import { Component, computed, input, ChangeDetectionStrategy } from '@angular/core';
import { TagModule } from '@openng/optimus-ui/tag';
import { TranslatePipe } from '../core/i18n/translate.pipe';
import type { LastScan } from '../core/api.models';
import { ScanStatusPipe } from './scan-status';

/** The tag's colour; the words are `SCAN_STATUS_KEYS`, shared with the history. */
const STATUS_SEVERITY: Record<string, 'success' | 'warn' | 'danger' | 'info'> = {
    pending: 'info',
    scanning: 'info',
    completed: 'success',
    failed: 'danger',
    cancelled: 'warn'
};

/**
 * The state of a target's last scan, repository or container alike.
 *
 * Extracted because the distinction it carries is too easy to lose when copied:
 * **"never scanned" is not "no problem"**, it is an absence of observation. A screen that
 * renders an empty cell in that case lies by omission.
 */
@Component({
    selector: 'app-last-scan',
    imports: [DatePipe, TagModule, TranslatePipe, ScanStatusPipe],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './last-scan.html'
})
export class LastScanTag {
    readonly scan = input.required<LastScan | null>();

    /** The tag's colour, worked out when the scan changes rather than on every pass; the words are the `scanStatus` pipe's. */
    readonly tone = computed(() => {
        const scan = this.scan();
        return (scan && STATUS_SEVERITY[scan.status]) ?? 'info';
    });
}
