import { DatePipe } from '@angular/common';
import { Component, inject, input, ChangeDetectionStrategy } from '@angular/core';
import { TagModule } from '@openng/optimus-ui/tag';
import { TranslatePipe } from '../core/i18n/translate.pipe';
import { I18nService } from '../core/i18n/i18n.service';
import type { LastScan } from '../core/api.models';
import { scanStatusLabel } from './scan-status';

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
    imports: [DatePipe, TagModule, TranslatePipe],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './last-scan.html'
})
export class LastScanTag {
    private readonly i18n = inject(I18nService);
    readonly scan = input.required<LastScan | null>();

    label(status: string): string {
        return scanStatusLabel(this.i18n, status);
    }

    severity(status: string): 'success' | 'warn' | 'danger' | 'info' {
        return STATUS_SEVERITY[status] ?? 'info';
    }
}
