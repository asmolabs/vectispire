import { DatePipe } from '@angular/common';
import { Component, computed, inject, signal, ChangeDetectionStrategy } from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { MessageModule } from '@openng/optimus-ui/message';
import { SelectModule } from '@openng/optimus-ui/select';
import { TagModule } from '@openng/optimus-ui/tag';
import { TargetsApi } from '../../core/api/targets.api';
import { OwaspApi } from '../../core/api/owasp.api';
import { DocumentsApi } from '../../core/api/documents.api';
import { I18nService } from '../../core/i18n/i18n.service';
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
import { OwaspGridComponent } from '@/app/shared/owasp-grid';
import { LatestRequest } from '@/app/core/latest-request';
import { messageOf } from '@/app/core/api-error';
import { OwaspWeekly } from './owasp-weekly';

@Component({
    selector: 'app-owasp',
    imports: [
        DatePipe,
        FormsModule,
        CardModule,
        ButtonModule,
        MessageModule,
        SelectModule,
        TagModule,
        OwaspGridComponent,
        OwaspWeekly,
        RouterLink,
        TranslatePipe
    ],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './owasp.html'
})
export class Owasp {
    private readonly reportRequest = new LatestRequest();

    private readonly targetsApi = inject(TargetsApi);
    private readonly owaspApi = inject(OwaspApi);
    private readonly documentsApi = inject(DocumentsApi);
    private readonly i18n = inject(I18nService);
    private readonly route = inject(ActivatedRoute);

    /**
     * Which of the two views, from the URL: the grid as it stands, or the same grid week by week.
     * A query parameter rather than a route of its own, so that the menu entry, the page title and
     * the guard stay one, and a link into the weekly view still says where it lands.
     */
    private readonly params = toSignal(this.route.queryParamMap);
    readonly weekly = computed(() => this.params()?.get('view') === 'weekly');

    selected: number | null = null;

    readonly repositories = signal<MonitoredRepository[]>([]);
    readonly report = signal<OwaspReport | null>(null);
    readonly running = signal(false);
    readonly error = signal<string | null>(null);

    constructor() {
        this.targetsApi.repositories().subscribe({
            next: (rows) => this.repositories.set(rows),
            error: () => this.error.set(this.i18n.t('owasp.repositories_load_failed'))
        });
    }

    loadLatest(): void {
        this.report.set(null);
        this.error.set(null);
        if (this.selected === null) {
            this.reportRequest.cancel();
            return;
        }
        this.reportRequest.run(this.owaspApi.owaspReport(this.selected), {
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
        this.documentsApi.downloadDocument(`/api/v1/repositories/${id}/owasp-review/export.pdf`).subscribe({
            next: (response) => saveDocument(response, `vectispire-owasp-${id}.pdf`),
            error: () => this.error.set(this.i18n.t('owasp.pdf_failed'))
        });
    }

    run(): void {
        if (this.selected === null) {
            return;
        }
        this.running.set(true);
        this.error.set(null);

        this.owaspApi.runOwaspReport(this.selected).subscribe({
            next: (report) => {
                this.report.set(report);
                this.running.set(false);
            },
            error: (response) => {
                this.running.set(false);
                this.error.set(messageOf(response, this.i18n.t('owasp.report_failed')));
            }
        });
    }
}
