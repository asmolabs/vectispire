import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { ButtonModule } from '@openng/optimus-ui/button';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { MessageModule } from '@openng/optimus-ui/message';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { AgentsPage } from './agents-page';

/**
 * The secret a newly declared agent authenticates with, shown once: the control plane keeps only its
 * hash, so this is the operator's one chance to copy it. Not closable but by the confirmation.
 */
@Component({
    selector: 'app-issued-secret-dialog',
    imports: [ButtonModule, DialogModule, MessageModule, TranslatePipe],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './issued-secret-dialog.html'
})
export class IssuedSecretDialog {
    protected readonly page = inject(AgentsPage);

    dismissSecret(): void {
        this.page.issuedSecret.set(null);
        this.page.secretVisible.set(false);
    }
}
