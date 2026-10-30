import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { ButtonModule } from '@openng/optimus-ui/button';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { MessageModule } from '@openng/optimus-ui/message';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { AgentsPage } from './agents-page';

/**
 * The private half of a freshly pinned signing key, shown once, with where it goes in the agent's
 * configuration. Same shape as the agent's secret for the same reason: the control plane does not
 * keep it.
 */
@Component({
    selector: 'app-signing-key-dialog',
    imports: [ButtonModule, DialogModule, MessageModule, TranslatePipe],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './signing-key-dialog.html'
})
export class SigningKeyDialog {
    protected readonly page = inject(AgentsPage);

    dismissSigningKey(): void {
        this.page.issuedSigningKey.set(null);
        this.page.signingKeyVisible.set(false);
    }
}
