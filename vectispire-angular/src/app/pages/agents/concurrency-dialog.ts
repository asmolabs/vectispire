import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from '@openng/optimus-ui/button';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { InputNumberModule } from '@openng/optimus-ui/inputnumber';
import { MessageModule } from '@openng/optimus-ui/message';
import { messageOf } from '../../core/api-error';
import { AgentsApi } from '../../core/api/agents.api';
import { I18nService } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { AgentsPage, CONCURRENCY_BOUNDS, withinBounds } from './agents-page';

/**
 * How many scans one agent runs at once. A form: the limit is required, a limit outside the bound is
 * refused before the server is asked, and the server's own refusal is said on the field.
 */
@Component({
    selector: 'app-concurrency-dialog',
    imports: [FormsModule, ButtonModule, DialogModule, InputNumberModule, MessageModule, TranslatePipe],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './concurrency-dialog.html'
})
export class ConcurrencyDialog {
    private readonly i18n = inject(I18nService);
    private readonly agentsApi = inject(AgentsApi);
    protected readonly page = inject(AgentsPage);
    protected readonly bounds = CONCURRENCY_BOUNDS;

    saveConcurrency(): void {
        const page = this.page;
        const agent = page.concurrencyAgent();
        if (!agent) return;
        const value = page.concurrencyValue();
        if (!withinBounds(value)) {
            page.concurrencyError.set(this.i18n.t('agents.error_concurrency_range'));
            return;
        }
        page.saving.set(true);
        this.agentsApi.setAgentMaxConcurrent(agent.id, value).subscribe({
            next: () => {
                page.saving.set(false);
                page.concurrencyVisible.set(false);
                page.reload();
            },
            error: (response) => {
                page.saving.set(false);
                page.concurrencyError.set(messageOf(response, this.i18n.t('agents.error_concurrency')));
            }
        });
    }
}
