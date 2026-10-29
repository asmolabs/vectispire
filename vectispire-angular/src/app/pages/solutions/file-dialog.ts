import { ChangeDetectionStrategy, Component, computed, inject } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from '@openng/optimus-ui/button';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { MessageModule } from '@openng/optimus-ui/message';
import { SelectModule } from '@openng/optimus-ui/select';
import { messageOf } from '../../core/api-error';
import { SolutionsApi } from '../../core/api/solutions.api';
import { I18nService } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { pathOf, SolutionsPage } from './solutions-page';

/**
 * A repository or an image filed into a project, or moved to another. **Filing is an access change**:
 * a grant on a project covers what it holds at each request, so the dialog says who gains and who
 * loses sight of it before the click, not the audit log after it. A form: the project is required.
 */
@Component({
    selector: 'app-file-dialog',
    imports: [FormsModule, ButtonModule, DialogModule, MessageModule, SelectModule, TranslatePipe],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './file-dialog.html'
})
export class FileDialog {
    private readonly api = inject(SolutionsApi);
    private readonly i18n = inject(I18nService);
    protected readonly page = inject(SolutionsPage);

    /** Every project the repository or image could move to, grouped by solution; the one it is in is left out. */
    readonly projectChoices = computed(() => {
        const current = this.page.filing()?.from?.project.id ?? null;
        return this.page
            .solutions()
            .map((solution) => ({
                label: solution.name,
                items: (solution.projects ?? [])
                    .filter((project) => project.id !== current)
                    .map((project) => ({ label: project.name, value: project.id }))
            }))
            .filter((group) => group.items.length > 0);
    });

    /**
     * Who gains and who loses sight of the repository or image. Said before the click: a move reads as
     * housekeeping and is, in fact, a change of access for everybody holding either project.
     */
    readonly filingConsequence = computed(() => {
        this.i18n.translations();
        const filing = this.page.filing();
        const target = this.page.projectPath(this.page.targetProjectId());
        if (!filing || !target) return null;
        return filing.from
            ? this.i18n.t('solutions.move_consequence', {
                  target: filing.target.ref.name,
                  from: pathOf(filing.from.solution, filing.from.project),
                  to: target
              })
            : this.i18n.t('solutions.file_consequence', { target: filing.target.ref.name, to: target });
    });

    saveFile(): void {
        const filing = this.page.filing();
        const projectId = this.page.targetProjectId();
        if (!filing || projectId === null) return;

        this.page.saving.set(true);
        this.page.formError.set(null);
        const { target } = filing;
        const request =
            target.kind === 'container'
                ? this.api.fileContainer(projectId, target.ref.id)
                : this.api.fileRepository(projectId, target.ref.id);
        request.subscribe({
            next: () => {
                this.page.saving.set(false);
                this.page.fileVisible.set(false);
                this.page.reload();
            },
            error: (failure) => {
                this.page.saving.set(false);
                this.page.formError.set(messageOf(failure, this.i18n.t('solutions.error_change')));
            }
        });
    }
}
