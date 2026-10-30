import { DatePipe } from '@angular/common';
import { ChangeDetectionStrategy, Component, computed, inject } from '@angular/core';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import type { AgentSummary, RunningScanItem } from '../../core/api.models';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { AgentsPage } from './agents-page';
import { DurationPipe } from './duration.pipe';

/** One agent as its row draws it: the labels split and the scan it runs looked up once per answer. */
export interface AgentRow {
    agent: AgentSummary;
    labels: string[];
    run: RunningScanItem | undefined;
}

/**
 * The registered agents: state, machine, labels, how credentials reach it and whether its results
 * are attested, its load, and the acts on it. Each act opens a dialog through the page, or is made
 * by the page directly (enable, signing key).
 */
@Component({
    selector: 'app-agent-table',
    imports: [DatePipe, ButtonModule, CardModule, TableModule, TagModule, TranslatePipe, DurationPipe],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './agent-table.html'
})
export class AgentTable {
    protected readonly page = inject(AgentsPage);

    readonly rows = computed<AgentRow[]>(() => {
        const running = this.page.runningByAgent();
        return this.page.agents().map((agent) => ({
            agent,
            labels: agent.labels ? agent.labels.split(',') : [],
            run: running.get(agent.id)
        }));
    });
}
