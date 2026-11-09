import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { RouterLink } from '@angular/router';
import { ButtonModule } from '@openng/optimus-ui/button';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { IssuesPage } from './issues-page';

/**
 * What the URL narrows the backlog by that no control shows: the solution, the project and the
 * identifier a link applied, as removable chips, and the OWASP view's drill-down said in words with
 * the way back. A list narrowed with nothing on screen saying so reads as a backlog that lost rows.
 */
@Component({
    selector: 'app-issue-scope',
    imports: [RouterLink, ButtonModule, TranslatePipe],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './issue-scope.html'
})
export class IssueScope {
    protected readonly page = inject(IssuesPage);
}
