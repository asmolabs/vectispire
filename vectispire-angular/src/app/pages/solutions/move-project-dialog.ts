import { ChangeDetectionStrategy, Component, computed, inject } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from '@openng/optimus-ui/button';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { SelectModule } from '@openng/optimus-ui/select';
import { messageOf } from '../../core/api-error';
import { SolutionsApi } from '../../core/api/solutions.api';
import type { Schema } from '../../core/api.models';
import { I18nService } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { NAME_MAX, PROJECT_NAME_TAKEN, problemType, SolutionsPage } from './solutions-page';

/**
 * A project moved to another solution, renamed on the way if its name is taken there — the refusal
 * keeps the dialog open beside the name field, since renaming is the way out. A form: the solution is
 * required.
 */
@Component({
    selector: 'app-move-project-dialog',
    imports: [FormsModule, ButtonModule, DialogModule, InputTextModule, MessageModule, SelectModule, TranslatePipe],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './move-project-dialog.html'
})
export class MoveProjectDialog {
    private readonly api = inject(SolutionsApi);
    private readonly i18n = inject(I18nService);
    protected readonly page = inject(SolutionsPage);

    protected readonly nameMax = NAME_MAX;

    /**
     * The other solutions only. Offering the current one would offer a click that changes nothing
     * and still reads, after the notice, as if something had moved.
     */
    readonly solutionChoices = computed(() => {
        const current = this.page.moving()?.solution.id ?? null;
        return this.page
            .solutions()
            .filter((solution) => solution.id !== current)
            .map((solution) => ({ label: solution.name, value: solution.id }));
    });

    /**
     * Only `solutionId`, and `name` when one was typed: a missing field is "unchanged" to the server,
     * so a move never rewrites a description it was not asked about.
     */
    saveMoveProject(): void {
        const moving = this.page.moving();
        const solutionId = this.page.targetSolutionId();
        if (!moving || solutionId === null) return;
        const target = this.page.solutions().find((solution) => solution.id === solutionId);
        if (!target) return;
        const name = this.page.moveName().trim();
        const body: Schema<'ProjectChange'> = name ? { solutionId, name } : { solutionId };

        this.page.saving.set(true);
        this.page.formError.set(null);
        this.page.moveNameTaken.set(null);
        this.api.updateProject(moving.project.id, body).subscribe({
            next: (moved) => {
                this.page.saving.set(false);
                this.page.moveVisible.set(false);
                this.page.notice.set(
                    this.i18n.t('solutions.project_moved', { project: moved.name, solution: target.name })
                );
                this.page.reload();
            },
            error: (failure) => {
                this.page.saving.set(false);
                // The dialog stays open with the name field beside the sentence: renaming is the way
                // out of this refusal, and closing would make the administrator start again.
                if (problemType(failure) === PROJECT_NAME_TAKEN) {
                    this.page.moveNameTaken.set(
                        this.i18n.t('solutions.move_project_name_taken', {
                            solution: target.name,
                            name: name || moving.project.name
                        })
                    );
                    return;
                }
                this.page.formError.set(messageOf(failure, this.i18n.t('solutions.error_change')));
            }
        });
    }
}
