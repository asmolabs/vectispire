import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { IconFieldModule } from '@openng/optimus-ui/iconfield';
import { InputIconModule } from '@openng/optimus-ui/inputicon';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { SelectModule } from '@openng/optimus-ui/select';
import { ToggleSwitchModule } from '@openng/optimus-ui/toggleswitch';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { SearchBound, SearchBoundHint } from '@/app/shared/search-bound';
import { IssuesPage } from './issues-page';

/**
 * The backlog's filters: state, severity, type, target, triage and the free-text search, then the four
 * one-way switches. Each writes the URL through `filtersChanged`, and each is lit by the URL in return,
 * so a link from the dashboard shows the filter it narrows by.
 */
@Component({
    selector: 'app-issue-filters',
    imports: [
        FormsModule,
        IconFieldModule,
        InputIconModule,
        InputTextModule,
        SelectModule,
        ToggleSwitchModule,
        TranslatePipe,
        SearchBound,
        SearchBoundHint
    ],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './issue-filters.html'
})
export class IssueFilters {
    protected readonly page = inject(IssuesPage);
}
