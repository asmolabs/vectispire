import { ChangeDetectionStrategy, Component, computed, inject } from '@angular/core';
import { CardModule } from '@openng/optimus-ui/card';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { AgentsPage } from './agents-page';
import { DurationPipe } from './duration.pipe';

/** The scans an agent is running now: target, branch, agent, label and how long it has been. */
@Component({
    selector: 'app-running-scans',
    imports: [CardModule, TableModule, TagModule, TranslatePipe, DurationPipe],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './running-scans.html'
})
export class RunningScans {
    protected readonly page = inject(AgentsPage);
    readonly runs = computed(() => this.page.activity()?.runningScans ?? []);
}
