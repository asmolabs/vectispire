import { CommonModule } from '@angular/common';
import { Component, computed, inject, signal } from '@angular/core';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { MessageModule } from '@openng/optimus-ui/message';
import { SelectModule } from '@openng/optimus-ui/select';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import { ApiService } from '../../core/api.service';
import { saveDocument } from '../../core/download';
import type { HistoryDossier, HistoryRepository, HistoryScan } from '../../core/api.models';

const SEVERITY_SEVERITY: Record<string, 'danger' | 'warn' | 'secondary'> = {
    critical: 'danger',
    high: 'danger',
    medium: 'warn',
    low: 'secondary',
    negligible: 'secondary',
    unknown: 'secondary'
};

/** Triage statuses in words. Open table: an unknown value is shown raw rather than hidden. */
const TRIAGE_LABELS: Record<string, string> = {
    under_review: 'Under review',
    not_affected: 'Not affected',
    affected: 'Affected',
    fixed: 'Fixed',
    accepted: 'Risk accepted',
    false_positive: 'False positive'
};

/**
 * The trail that shows a finding was taken into account.
 *
 * **Not another view of the backlog.** The issues screen answers "what is open now"; this one
 * answers "what did we see, when, on which version, and what did we decide" — for a reader who
 * has to be convinced after the fact and was not there.
 *
 * The exports are on this page rather than behind a menu because they are the point of it: what
 * gets handed to an auditor is a file, not a URL into an application they cannot log into.
 */
@Component({
    selector: 'app-history',
    standalone: true,
    imports: [CommonModule, CardModule, TableModule, TagModule, MessageModule, ButtonModule, SelectModule],
    templateUrl: './history.html'
})
export class History {
    private readonly api = inject(ApiService);

    readonly repositories = signal<HistoryRepository[]>([]);
    readonly dossier = signal<HistoryDossier | null>(null);
    readonly loadingList = signal(true);
    readonly error = signal<string | null>(null);

    readonly selectedId = computed(() => this.dossier()?.repository.id ?? null);

    constructor() {
        this.api.historyRepositories().subscribe({
            next: (rows) => {
                this.repositories.set(rows);
                this.loadingList.set(false);
                // Opening the most recently scanned target rather than none: the page exists to
                // be read, and an empty right-hand side is a click everybody has to make.
                if (rows.length > 0) {
                    this.open(rows[0]);
                }
            },
            error: () => {
                this.loadingList.set(false);
                this.error.set('The history could not be loaded.');
            }
        });
    }

    open(repository: HistoryRepository): void {
        this.api.historyDossier(repository.id).subscribe({
            next: (file) => this.dossier.set(file),
            error: () => this.error.set('This target’s dossier could not be loaded.')
        });
    }

    download(format: 'pdf' | 'csv'): void {
        const id = this.selectedId();
        if (id === null) {
            return;
        }
        // Through HttpClient, never a navigation: there is no session cookie here. The token
        // lives in memory and only the interceptor puts it on a request.
        this.api.downloadDocument(`/api/v1/history/repositories/${id}/export.${format}`).subscribe({
            next: (response) => saveDocument(response, `zanshin-history-${id}.${format}`),
            error: () => this.error.set('The export could not be produced.')
        });
    }

    severityOf(severity: string | null): 'danger' | 'warn' | 'secondary' {
        return SEVERITY_SEVERITY[severity ?? 'unknown'] ?? 'secondary';
    }

    triageLabel(status: string | null): string {
        if (!status) {
            return '—';
        }
        return TRIAGE_LABELS[status] ?? status;
    }

    component(issue: { packageName: string | null; packageVersion: string | null; filePath: string | null }): string {
        if (issue.packageName) {
            return issue.packageVersion ? `${issue.packageName} ${issue.packageVersion}` : issue.packageName;
        }
        return issue.filePath ?? '—';
    }
}
