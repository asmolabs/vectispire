import { LowerCasePipe } from '@angular/common';
import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { AgentsPage } from './agents-page';
import { DurationPipe } from './duration.pipe';

/** The four tiles: agents online, scans running, scans waiting, scans finished in a day. */
@Component({
    selector: 'app-agent-kpis',
    imports: [LowerCasePipe, TranslatePipe, DurationPipe],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './agent-kpis.html'
})
export class AgentKpis {
    protected readonly page = inject(AgentsPage);
}
