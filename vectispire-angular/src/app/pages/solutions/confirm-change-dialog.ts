import { ChangeDetectionStrategy, Component, computed, inject } from '@angular/core';
import { ButtonModule } from '@openng/optimus-ui/button';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { messageOf } from '../../core/api-error';
import { SolutionsApi } from '../../core/api/solutions.api';
import { I18nService } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { pathOf, SolutionsPage } from './solutions-page';

/** The three changes that take something away from somebody, said in full and confirmed first. */
@Component({
    selector: 'app-confirm-change-dialog',
    imports: [ButtonModule, DialogModule, TranslatePipe],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './confirm-change-dialog.html'
})
export class ConfirmChangeDialog {
    private readonly api = inject(SolutionsApi);
    private readonly i18n = inject(I18nService);
    protected readonly page = inject(SolutionsPage);

    /**
     * What the confirmation says, in full. Deleting a project detaches its repositories **and**
     * revokes the grants naming it — the two consequences an administrator would otherwise learn
     * from the account that stopped seeing something.
     */
    readonly confirmText = computed(() => {
        this.i18n.translations();
        const pending = this.page.pending();
        if (!pending) return '';
        switch (pending.kind) {
            case 'delete-solution':
                return this.i18n.t('solutions.delete_solution_consequence', { name: pending.solution.name });
            case 'delete-project':
                return this.i18n.t('solutions.delete_project_consequence', {
                    name: pathOf(pending.solution, pending.project),
                    count: pending.project.repositoryCount,
                    images: pending.project.containerCount
                });
            case 'unfile':
                return this.i18n.t('solutions.unfile_consequence', {
                    target: pending.target.ref.name,
                    project: pathOf(pending.solution, pending.project)
                });
        }
    });

    readonly confirmHeader = computed(() => {
        this.i18n.translations();
        switch (this.page.pending()?.kind) {
            case 'delete-solution':
                return this.i18n.t('solutions.header_delete_solution');
            case 'delete-project':
                return this.i18n.t('solutions.header_delete_project');
            case 'unfile':
                return this.i18n.t('solutions.header_unfile');
            default:
                return '';
        }
    });

    confirm(): void {
        const pending = this.page.pending();
        if (!pending) return;
        const request =
            pending.kind === 'delete-solution'
                ? this.api.deleteSolution(pending.solution.id)
                : pending.kind === 'delete-project'
                  ? this.api.deleteProject(pending.project.id)
                  : pending.target.kind === 'container'
                    ? this.api.unfileContainer(pending.project.id, pending.target.ref.id)
                    : this.api.unfileRepository(pending.project.id, pending.target.ref.id);

        this.page.saving.set(true);
        request.subscribe({
            next: () => {
                this.page.saving.set(false);
                this.page.confirmVisible.set(false);
                this.page.reload();
            },
            error: (failure) => {
                this.page.saving.set(false);
                this.page.confirmVisible.set(false);
                // The 409 on a solution that still holds projects carries the server's sentence,
                // which says what to do; a generic "could not delete" would not.
                this.page.error.set(messageOf(failure, this.i18n.t('solutions.error_change')));
                this.page.reload(true);
            }
        });
    }
}
