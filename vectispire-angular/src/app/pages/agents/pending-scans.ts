import { ChangeDetectionStrategy, Component, computed, inject } from '@angular/core';
import { CardModule } from '@openng/optimus-ui/card';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { AgentsPage } from './agents-page';
import { DurationPipe } from './duration.pipe';

/**
 * The queue, in the order it is served, each scan said routable or blocked — blocked meaning no
 * enabled agent carries the label it requires.
 */
@Component({
    selector: 'app-pending-scans',
    imports: [CardModule, TableModule, TagModule, TranslatePipe, DurationPipe],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './pending-scans.html'
})
export class PendingScans {
    protected readonly page = inject(AgentsPage);
    readonly waiting = computed(() => this.page.activity()?.pendingScans ?? []);
}
