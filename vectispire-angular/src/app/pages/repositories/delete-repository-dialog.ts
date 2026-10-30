import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { ButtonModule } from '@openng/optimus-ui/button';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { TargetsApi } from '../../core/api/targets.api';
import { I18nService } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { RepositoriesPage } from './repositories-page';

/** A repository removed from monitoring, confirmed first. */
@Component({
    selector: 'app-delete-repository-dialog',
    imports: [ButtonModule, DialogModule, TranslatePipe],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './delete-repository-dialog.html'
})
export class DeleteRepositoryDialog {
    private readonly i18n = inject(I18nService);
    private readonly targetsApi = inject(TargetsApi);
    protected readonly page = inject(RepositoriesPage);

    confirmDelete(): void {
        const repository = this.page.pendingDelete();
        if (!repository) return;
        this.page.saving.set(true);
        this.targetsApi.deleteRepository(repository.id).subscribe({
            next: () => {
                this.page.saving.set(false);
                this.page.deleteVisible.set(false);
                this.page.reload();
            },
            error: () => {
                this.page.saving.set(false);
                this.page.deleteVisible.set(false);
                this.page.error.set(this.i18n.t('repositories.error_delete'));
            }
        });
    }
}
