import { CommonModule } from '@angular/common';
import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { MessageModule } from '@openng/optimus-ui/message';
import { SelectModule } from '@openng/optimus-ui/select';
import { TagModule } from '@openng/optimus-ui/tag';
import { ApiService } from '../../core/api.service';
import { saveDocument } from '../../core/download';
import type { MonitoredRepository, OwaspReport } from '../../core/api.models';

/**
 * The OWASP Top 10 posture report, written by the configured model.
 *
 * **Repositories only.** Half the Top 10 describes an application and the decisions behind it —
 * access control, insecure design, logging. A container image has an inventory and a base
 * distribution, and a report filing its CVEs under "Broken Access Control" would have the right
 * headings and nothing behind them.
 *
 * **On a button, never on a scan.** A model call takes tens of seconds and answers slightly
 * differently each time; hanging it off every scan would make the queue unpredictable and fill
 * the table with reports nobody read.
 */
import { TranslatePipe } from '../../core/i18n/translate.pipe';

@Component({
    selector: 'app-owasp',
    standalone: true,
    imports: [CommonModule, FormsModule, CardModule, ButtonModule, MessageModule, SelectModule, TagModule, TranslatePipe],
    templateUrl: './owasp.html'
})
export class Owasp {
    private readonly api = inject(ApiService);

    selected: number | null = null;

    readonly repositories = signal<MonitoredRepository[]>([]);
    readonly report = signal<OwaspReport | null>(null);
    readonly running = signal(false);
    readonly error = signal<string | null>(null);

    constructor() {
        this.api.repositories().subscribe({
            next: (rows) => this.repositories.set(rows),
            error: () => this.error.set('The repositories could not be loaded.')
        });
    }

    loadLatest(): void {
        this.report.set(null);
        this.error.set(null);
        if (this.selected === null) {
            return;
        }
        this.api.owaspReport(this.selected).subscribe({
            next: (report) => this.report.set(report),
            // A 404 here means "none yet", which is a state and not a failure.
            error: () => this.report.set(null)
        });
    }

    downloadPdf(): void {
        const id = this.selected;
        if (id === null) {
            return;
        }
        // Through HttpClient, never a navigation: the token is in memory and only the
        // interceptor puts it on a request. A navigation carries none, and the browser saves the
        // 401's empty body as a zero-byte file.
        this.api.downloadDocument(`/api/v1/repositories/${id}/owasp-review/export.pdf`).subscribe({
            next: (response) => saveDocument(response, `zanshin-owasp-${id}.pdf`),
            error: () => this.error.set('The PDF could not be produced.')
        });
    }

    run(): void {
        if (this.selected === null) {
            return;
        }
        this.running.set(true);
        this.error.set(null);

        this.api.runOwaspReport(this.selected).subscribe({
            next: (report) => {
                this.report.set(report);
                this.running.set(false);
            },
            error: (response) => {
                this.running.set(false);
                this.error.set(response?.error?.message ?? 'The report could not be produced.');
            }
        });
    }
}
