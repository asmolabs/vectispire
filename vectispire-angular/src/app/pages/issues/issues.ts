import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { AiAdvisorDialog } from './ai-advisor-dialog';
import { IssueFilters } from './issue-filters';
import { IssueScope } from './issue-scope';
import { IssueTable } from './issue-table';
import { IssuesPage } from './issues-page';
import { TriageDialog } from './triage-dialog';

/**
 * The backlog, and triage.
 *
 * The screen is the frame: the backlog, its filters and the URL they live in are `IssuesPage`,
 * provided here so each visit starts from nothing; the filters, the scope, the table and the two
 * dialogs are components of their own. The table hands its row acts to the dialogs through this
 * template, and a decision saved reads the page again.
 */
@Component({
    selector: 'zs-issues',
    imports: [TranslatePipe, AiAdvisorDialog, IssueFilters, IssueScope, IssueTable, TriageDialog],
    providers: [IssuesPage],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './issues.html'
})
export class Issues {
    protected readonly page = inject(IssuesPage);
}
