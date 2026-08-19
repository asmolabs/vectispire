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
const STATUS_LABELS: Record<string, { label: string; severity: 'success' | 'warn' | 'danger' | 'info' }> = {
    pending: { label: 'Queued', severity: 'info' },
    scanning: { label: 'Running', severity: 'info' },
    completed: { label: 'Completed', severity: 'success' },
    failed: { label: 'Failed', severity: 'danger' },
    cancelled: { label: 'Cancelled', severity: 'warn' }
};

@Component({
    selector: 'app-last-scan',
    standalone: true,
    imports: [CommonModule, TagModule],
    template: `
        @if (scan(); as value) {
            <p-tag [value]="label(value.status)" [severity]="severity(value.status)" />
            <div class="text-sm text-muted-color mt-1">{{ value.createdAt | date: 'dd/MM/yyyy HH:mm' }}</div>
            @if (value.error) {
                <div class="text-sm text-red-500 mt-1">{{ value.error }}</div>
            }
        } @else {
            <span class="text-muted-color">Never scanned</span>
        }
    `
})
export class LastScanTag {
    readonly scan = input.required<LastScan | null>();

    /** Closed table: a status outside the vocabulary is shown raw rather than hidden behind
     *  a reassuring label. */
    label(status: string): string {
        return STATUS_LABELS[status]?.label ?? status;
    }

    severity(status: string): 'success' | 'warn' | 'danger' | 'info' {
        return STATUS_LABELS[status]?.severity ?? 'info';
    }
}
