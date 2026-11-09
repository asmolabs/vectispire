import { ChangeDetectionStrategy, Component, computed, inject } from '@angular/core';
import { MessageModule } from '@openng/optimus-ui/message';
import { I18nService } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { AgentsPage } from './agents-page';

/**
 * What the screen says above the figures: a refusal, a change made, the labels nobody carries, the
 * credentialed scans nobody able to be handed the credential can take, a built-in worker whose executor does
 * not answer, and a failed activity read.
 */
@Component({
    selector: 'app-agent-notices',
    imports: [MessageModule, TranslatePipe],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './agent-notices.html'
})
export class AgentNotices {
    private readonly i18n = inject(I18nService);
    protected readonly page = inject(AgentsPage);

    /** The labels those scans require, `''` — no label — said in words. */
    readonly credentialedLabels = computed(() => {
        this.i18n.translations();
        return (this.page.credentialedBacklog()?.labels ?? [])
            .map((label) => (label === '' ? this.i18n.t('agents.credentialed_backlog.no_label') : label))
            .join(', ');
    });

    readonly keptAgents = computed(() => (this.page.credentialedBacklog()?.keptAgents ?? []).join(', '));

    /**
     * Why the built-in worker claims nothing, in its executor's words — or `null` when it is not meant to run,
     * or runs. A worker whose daemon stopped answering takes no scan by design; it is not a row of the table,
     * so this is the one place the screen can say so.
     */
    readonly builtInDown = computed(() => {
        const worker = this.page.builtInWorker();
        if (!worker?.runsScans) return null;
        const down = (worker.executors ?? []).find((executor) => !executor.available);
        return down ? (down.detail ?? down.kind) : null;
    });
}
