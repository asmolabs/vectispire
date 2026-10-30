import { ChangeDetectionStrategy, Component, inject, OnInit } from '@angular/core';
import { ButtonModule } from '@openng/optimus-ui/button';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { AgentKpis } from './agent-kpis';
import { AgentNotices } from './agent-notices';
import { AgentTable } from './agent-table';
import { AgentsPage } from './agents-page';
import { ConcurrencyDialog } from './concurrency-dialog';
import { DeclareAgentDialog } from './declare-agent-dialog';
import { DeleteAgentDialog } from './delete-agent-dialog';
import { IssuedSecretDialog } from './issued-secret-dialog';
import { PendingScans } from './pending-scans';
import { ResetSealingDialog } from './reset-sealing-dialog';
import { RunningScans } from './running-scans';
import { SigningKeyDialog } from './signing-key-dialog';

/**
 * The scan executors: what is running and waiting, the figures over a day, and the registered agents
 * with the acts on them. Administrators only; the server refuses anyone else.
 *
 * The screen is the frame: the fleet and what each dialog is open on are `AgentsPage`, provided here
 * so each visit starts from nothing; the notices, the tiles, the two queues, the agent table and the
 * six dialogs are components of their own.
 */
@Component({
    selector: 'app-agents',
    imports: [
        ButtonModule,
        TranslatePipe,
        AgentKpis,
        AgentNotices,
        AgentTable,
        ConcurrencyDialog,
        DeclareAgentDialog,
        DeleteAgentDialog,
        IssuedSecretDialog,
        PendingScans,
        ResetSealingDialog,
        RunningScans,
        SigningKeyDialog
    ],
    providers: [AgentsPage],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './agents.html'
})
export class Agents implements OnInit {
    protected readonly page = inject(AgentsPage);

    ngOnInit(): void {
        this.page.reload();
        this.page.refreshActivity();
    }
}
