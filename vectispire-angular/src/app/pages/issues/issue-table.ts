import { DatePipe } from '@angular/common';
import { ChangeDetectionStrategy, Component, computed, inject, output } from '@angular/core';
import { RouterLink } from '@angular/router';
import { ButtonModule } from '@openng/optimus-ui/button';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import type { Issue } from '@/app/core/api.models';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { SeverityLabelPipe, severityTone, type SeverityTone } from '@/app/shared/severity';
import { IssuesPage } from './issues-page';

/** What a row shows of its issue in words and colours, worked out once per page of the list. */
interface IssueView {
    typeText: string;
    severityTone: SeverityTone;
    sla: { label: string; tone: 'danger' | 'warn' | 'secondary' } | null;
    triageText: string;
    triageTone: 'success' | 'danger' | 'warn' | 'secondary';
    requestedText: string;
    reviewSoon: boolean;
}

/**
 * One page of the backlog, its selection, and the way through the pages. The acts on a row — triage,
 * the advisor — and the bulk triage are handed to the page, which owns the dialogs.
 *
 * What each row shows is computed when the page of issues or the language changes, not asked of five
 * methods per row on every pass; a review date's nearness is judged then too, against that moment.
 */
@Component({
    selector: 'app-issue-table',
    imports: [DatePipe, RouterLink, ButtonModule, TableModule, TagModule, TranslatePipe, SeverityLabelPipe],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './issue-table.html'
})
export class IssueTable {
    protected readonly page = inject(IssuesPage);

    readonly triage = output<Issue>();
    readonly advise = output<Issue>();
    readonly bulkTriage = output<void>();

    protected readonly views = computed(() => {
        const views: Record<number, IssueView> = {};
        // Read for its dependency: the labels below follow the language.
        this.page.triageOptions();
        for (const issue of this.page.issues()) {
            const sla = this.page.slaLabel(issue);
            views[issue.id] = {
                typeText: this.page.typeLabel(issue.type),
                severityTone: severityTone(issue.severity),
                sla: sla === null ? null : { label: sla, tone: this.page.slaColour(issue) },
                triageText: this.page.triageLabel(issue.triageStatus),
                triageTone: this.page.triageColour(issue.triageStatus),
                requestedText: issue.triageRequestedStatus ? this.page.triageLabel(issue.triageRequestedStatus) : '',
                reviewSoon: this.page.reviewIsImminent(issue)
            };
        }
        return views;
    });
}
