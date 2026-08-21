import { CommonModule } from '@angular/common';
import { Component, computed, inject, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { CardModule } from '@openng/optimus-ui/card';
import { MessageModule } from '@openng/optimus-ui/message';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import { ApiService } from '../../core/api.service';
import type { DashboardOverview } from '../../core/api.models';
import { LastScanTag } from '../../shared/last-scan';

/** The severities in descending order, with their colour. A fixed order, not derived from the
 *  data: otherwise two successive loads could present them differently. */
const SEVERITIES = [
    { key: 'critical', label: 'Critical', severity: 'danger' as const },
    { key: 'high', label: 'High', severity: 'warn' as const },
    { key: 'medium', label: 'Medium', severity: 'secondary' as const },
    { key: 'low', label: 'Low', severity: 'secondary' as const }
];

@Component({
    selector: 'app-dashboard',
    standalone: true,
    imports: [CommonModule, RouterLink, CardModule, MessageModule, TableModule, TagModule, LastScanTag],
    templateUrl: './dashboard.html'
})
export class Dashboard {
    private readonly api = inject(ApiService);
    readonly severities = SEVERITIES;

    readonly data = signal<DashboardOverview | null>(null);
    readonly loading = signal(true);
    readonly error = signal<string | null>(null);

    constructor() {
        this.api.dashboard().subscribe({
            next: (overview) => {
                this.data.set(overview);
                this.loading.set(false);
            },
            error: () => {
                this.error.set('Could not load the dashboard.');
                this.loading.set(false);
            }
        });
    }

    /** Three violations at most: beyond that the row becomes a wall of text and the table
     *  stops serving its purpose, which is spotting what to handle. */
    firstViolations(violations: DashboardOverview['failing'][number]['violations']) {
        return violations.slice(0, 3);
    }
}
