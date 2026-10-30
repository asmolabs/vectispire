import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { ButtonModule } from '@openng/optimus-ui/button';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { messageOf } from '../../core/api-error';
import { AgentsApi } from '../../core/api/agents.api';
import { I18nService } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { AgentsPage } from './agents-page';

/** An agent deleted, once confirmed; a refusal closes the dialog and is said above the page. */
@Component({
    selector: 'app-delete-agent-dialog',
    imports: [ButtonModule, DialogModule, TranslatePipe],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './delete-agent-dialog.html'
})
export class DeleteAgentDialog {
    private readonly i18n = inject(I18nService);
    private readonly agentsApi = inject(AgentsApi);
    protected readonly page = inject(AgentsPage);

    confirmDelete(): void {
        const page = this.page;
        const agent = page.pendingDelete();
        if (!agent) return;
        this.agentsApi.deleteAgent(agent.id).subscribe({
            next: () => {
                page.deleteVisible.set(false);
                page.pendingDelete.set(null);
                page.reload();
            },
            error: (response) => {
                page.deleteVisible.set(false);
                page.pendingDelete.set(null);
                page.error.set(messageOf(response, this.i18n.t('agents.error_delete')));
            }
        });
    }
}
