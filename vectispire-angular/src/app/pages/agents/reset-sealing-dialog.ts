import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { ButtonModule } from '@openng/optimus-ui/button';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { messageOf } from '../../core/api-error';
import { AgentsApi } from '../../core/api/agents.api';
import { I18nService } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { AgentsPage } from './agents-page';

/**
 * An agent's sealing key forgotten (ADR 0031), once confirmed: its delegated scans are withheld, not
 * failed, until it proves a new key — which is why the dialog says so before the click.
 */
@Component({
    selector: 'app-reset-sealing-dialog',
    imports: [ButtonModule, DialogModule, TranslatePipe],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './reset-sealing-dialog.html'
})
export class ResetSealingDialog {
    private readonly i18n = inject(I18nService);
    private readonly agentsApi = inject(AgentsApi);
    protected readonly page = inject(AgentsPage);

    confirmResetSealing(): void {
        const page = this.page;
        const agent = page.pendingResetSealing();
        if (!agent) return;
        page.busy.set(agent.id);
        page.error.set(null);
        page.notice.set(null);
        this.agentsApi.resetAgentSealingKey(agent.id).subscribe({
            next: () => {
                page.busy.set(null);
                page.resetSealingVisible.set(false);
                page.pendingResetSealing.set(null);
                page.notice.set(this.i18n.t('agents.reset_sealing_notice', { name: agent.name }));
                page.reload();
            },
            error: (response) => {
                page.busy.set(null);
                page.resetSealingVisible.set(false);
                page.pendingResetSealing.set(null);
                // A 404 is an agent deleted meanwhile, in another tab: said as such, and the list
                // reloaded so the row it was clicked on goes away.
                page.error.set(
                    (response as { status?: number } | null)?.status === 404
                        ? this.i18n.t('agents.error_not_found')
                        : messageOf(response, this.i18n.t('agents.error_reset_sealing'))
                );
                page.reload(true);
            }
        });
    }
}
