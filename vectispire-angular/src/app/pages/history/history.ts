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
import type { HistoryDossier, HistoryIssue, HistoryRepository, HistoryScan } from '../../core/api.models';

const SEVERITY_SEVERITY: Record<string, 'danger' | 'warn' | 'secondary'> = {
    critical: 'danger',
    high: 'danger',
    medium: 'warn',
    low: 'secondary',
    negligible: 'secondary',
    unknown: 'secondary'
};

/**
 * Severity as a rank, in the order the issues screen already uses.
 *
 * **Numeric and not the word, because the word sorts wrong.** Alphabetically "low" falls between
 * "high" and "medium", so a table sorting the label puts a low finding above a medium one — a
 * reader scanning the top of the list for what matters would be reading the wrong rows. The rank
 * is attached to each row for the same reason: the table sorts what it is given, and giving it
 * the label is giving it the alphabet.
 *
 * An unrecognised value ranks last rather than first: a severity nobody has mapped is not
 * evidence of danger, and putting it above "critical" would push the real ones down.
 */
const SEVERITY_RANK: Record<string, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    negligible: 4,
    unknown: 5
};

/** A finding carrying its rank, so the column can sort on a number the reader never sees. */
type RankedIssue = HistoryIssue & { severityRank: number };

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
import { I18nService } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';

@Component({
    selector: 'app-history',
    standalone: true,
    imports: [CommonModule, CardModule, TableModule, TagModule, MessageModule, ButtonModule, SelectModule, TranslatePipe],
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
            next: (file) => this.dossier.set(ranked(file)),
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
            next: (response) => saveDocument(response, `vectispire-history-${id}.${format}`),
            error: () => this.error.set('The export could not be produced.')
        });
    }

    downloadVex(scanId: number): void {
        this.api.getScanVex(scanId).subscribe({
            next: (vexDoc) => {
                const blob = new Blob([JSON.stringify(vexDoc, null, 2)], { type: 'application/json' });
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `scan-${scanId}-openvex.json`;
                a.click();
                window.URL.revokeObjectURL(url);
            },
            error: () => this.error.set('Could not download OpenVEX document for this scan.')
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

/**
 * Ranks and orders every scan's findings, worst first.
 *
 * <p>Done on arrival rather than left to the table's default order, which is the server's — the
 * order rows were written, in which a critical finding can sit below thirty low ones. The reader
 * of this page is answering "was this taken seriously"; the answer must be at the top.
 *
 * <p>Copies rather than sorting in place: the dossier is what the exports read, and a shared array
 * reordered underneath them would change a PDF's contents as a side effect of opening a screen.
 */
function ranked(dossier: HistoryDossier): HistoryDossier {
    return {
        ...dossier,
        scans: dossier.scans.map((scan) => ({
            ...scan,
            issues: scan.issues
                .map((issue): RankedIssue => ({
                    ...issue,
                    severityRank: SEVERITY_RANK[issue.severity ?? 'unknown'] ?? SEVERITY_RANK['unknown']
                }))
                .sort((left, right) => left.severityRank - right.severityRank)
        }))
    };
}
