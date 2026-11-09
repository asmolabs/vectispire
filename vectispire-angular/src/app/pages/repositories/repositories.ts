import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { ButtonModule } from '@openng/optimus-ui/button';
import { MessageModule } from '@openng/optimus-ui/message';
import { RuleCoverageBanner } from '@/app/shared/rule-coverage-banner';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { CicdDialog } from './cicd-dialog';
import { DeleteRepositoryDialog } from './delete-repository-dialog';
import { ImportsDialog } from './imports-dialog';
import { RepositoriesPage } from './repositories-page';
import { RepositoryFormDialog } from './repository-form-dialog';
import { RepositoryList } from './repository-list';
import { ScorecardDialog } from './scorecard-dialog';

export { httpsHost, urlCarriesSecret, urlTransport, type CredentialKind } from './repository-model';

/**
 * The monitored repositories.
 *
 * The screen is the frame: the list, its polling and the scans queued from it are `RepositoriesPage`,
 * provided here so each visit starts from nothing; the list and the five dialogs are components of their
 * own, the form opened from this template on a new repository or one of the list's.
 */
@Component({
    selector: 'app-repositories',
    imports: [
        ButtonModule,
        MessageModule,
        TranslatePipe,
        RuleCoverageBanner,
        CicdDialog,
        DeleteRepositoryDialog,
        ImportsDialog,
        RepositoryFormDialog,
        RepositoryList,
        ScorecardDialog
    ],
    providers: [RepositoriesPage],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './repositories.html'
})
export class Repositories {
    protected readonly page = inject(RepositoriesPage);
}
