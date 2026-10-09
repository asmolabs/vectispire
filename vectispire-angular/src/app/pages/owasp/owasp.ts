import { DatePipe } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { Component, computed, inject, signal, ChangeDetectionStrategy } from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { ActivatedRoute, Params, Router, RouterLink } from '@angular/router';
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
import type { MonitoredRepository, OwaspBlock, OwaspReport } from '../../core/api.models';

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
import { OwaspScopePicker } from '@/app/shared/owasp-scope-picker';
import { OwaspScope, readScope, sameScope, scopeParams } from '@/app/shared/owasp-scope';
import { OwaspWeekly } from './owasp-weekly';
import { issueLinker, LinkedText, Segment } from './report-links';

/** A block as the card renders it: its prose cut into text and links, and its category's count. */
export interface RenderedBlock {
    block: OwaspBlock;
    text: Segment[];
    rows: Segment[][][];
    /** The category's current open, unsettled issues; `null` where the block names no category. */
    findings: number | null;
    /** The backlog those findings are, as `/issues` reads it. */
    findingsParams: Params | null;
}

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
        OwaspScopePicker,
        OwaspWeekly,
        LinkedText,
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
    private readonly router = inject(Router);

    /**
     * Which of the two views, from the URL: the grid as it stands, or the same grid week by week.
     * A query parameter rather than a route of its own, so that the menu entry, the page title and
     * the guard stay one, and a link into the weekly view still says where it lands.
     */
    private readonly params = toSignal(this.route.queryParamMap);
    readonly weekly = computed(() => this.params()?.get('view') === 'weekly');

    /**
     * The project or solution both views are read over, from the same two parameters: switching views
     * keeps it, and a link to either reproduces it. Compared by value, so that a navigation which does
     * not move the scope — the weekly view picking a week — does not read the grid again.
     */
    readonly scope = computed<OwaspScope>(
        () => {
            const params = this.params();
            return params ? readScope(params) : null;
        },
        { equal: sameScope }
    );
    readonly currentParams = computed<Params>(() => scopeParams(this.scope()));
    readonly weeklyParams = computed<Params>(() => ({ view: 'weekly', ...scopeParams(this.scope()) }));

    /** The current view's scope, into its URL; the grid reads it back from there. */
    scopeChanged(scope: OwaspScope): void {
        void this.router.navigate([], { relativeTo: this.route, queryParams: scopeParams(scope), replaceUrl: true });
    }

    selected: number | null = null;

    readonly repositories = signal<MonitoredRepository[]>([]);
    readonly report = signal<OwaspReport | null>(null);
    /**
     * The repository the report shown describes, set with it: `selected` is a plain field that has
     * already moved when the picker changes, and a link built from it would open another
     * repository's backlog under this report.
     */
    private readonly reportRepository = signal<number | null>(null);
    /** No report has been written for the selected repository — a state, told apart from a failed read. */
    readonly noReport = signal(false);

    readonly blocks = computed<RenderedBlock[]>(() => {
        const report = this.report();
        if (!report) return [];
        const repositoryId = this.reportRepository();
        const link = issueLinker(report.issueLinks, repositoryId);
        return report.blocks.map((block) => {
            const findings = block.category ? (report.categoryFindings?.[block.category] ?? null) : null;
            return {
                block,
                text: link(block.text),
                rows: (block.rows ?? []).map((row) => row.map((cell) => link(cell))),
                findings,
                // The grid's shape (`OwaspGridComponent.openParams`), narrowed to this repository:
                // the count is the `total` of exactly this list, so the link and the figure agree.
                findingsParams:
                    findings !== null && repositoryId !== null
                        ? { repository_id: repositoryId, owasp_category: block.category, unsettled: 'true' }
                        : null
            };
        });
    });
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
        this.noReport.set(false);
        this.error.set(null);
        const id = this.selected;
        if (id === null) {
            this.reportRequest.cancel();
            return;
        }
        this.reportRequest.run(this.owaspApi.owaspReport(id), {
            next: (report) => this.show(report, id),
            error: (response: unknown) => {
                // A 404 means "none yet", which is a state and not a failure. Anything else is a
                // failure: read as "none yet", a 500 invited the reader to run a report that exists.
                if (response instanceof HttpErrorResponse && response.status === 404) {
                    this.noReport.set(true);
                } else {
                    this.error.set(messageOf(response, this.i18n.t('owasp.load_failed')));
                }
            }
        });
    }

    private show(report: OwaspReport, repositoryId: number): void {
        this.reportRepository.set(repositoryId);
        this.report.set(report);
        this.noReport.set(false);
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
        const id = this.selected;
        if (id === null) {
            return;
        }
        this.running.set(true);
        this.error.set(null);

        this.owaspApi.runOwaspReport(id).subscribe({
            next: (report) => {
                this.show(report, id);
                this.running.set(false);
            },
            error: (response) => {
                this.running.set(false);
                this.error.set(messageOf(response, this.i18n.t('owasp.report_failed')));
            }
        });
    }
}
