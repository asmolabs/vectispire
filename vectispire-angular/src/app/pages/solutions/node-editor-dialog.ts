import { ChangeDetectionStrategy, Component, computed, inject } from '@angular/core';
import { FormsModule } from '@angular/forms';
import type { Observable } from 'rxjs';
import { ButtonModule } from '@openng/optimus-ui/button';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { messageOf } from '../../core/api-error';
import { SolutionsApi } from '../../core/api/solutions.api';
import { I18nService } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import {
    DESCRIPTION_MAX,
    Editing,
    NAME_MAX,
    PROJECT_NAME_TAKEN,
    problemType,
    SOLUTION_NAME_TAKEN,
    SolutionsPage
} from './solutions-page';

/**
 * A solution or a project created or renamed, with its description. A form: the name is required and
 * stopped at the server's length as it is typed; a name already taken is said in the dialog, which
 * stays open on what was typed.
 */
@Component({
    selector: 'app-node-editor-dialog',
    imports: [FormsModule, ButtonModule, DialogModule, InputTextModule, MessageModule, TranslatePipe],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './node-editor-dialog.html'
})
export class NodeEditorDialog {
    private readonly api = inject(SolutionsApi);
    private readonly i18n = inject(I18nService);
    protected readonly page = inject(SolutionsPage);

    protected readonly nameMax = NAME_MAX;
    protected readonly descriptionMax = DESCRIPTION_MAX;

    readonly editorHeader = computed(() => {
        this.i18n.translations();
        const editing = this.page.editing();
        if (!editing) return '';
        if (editing.kind === 'solution') {
            return editing.solution
                ? this.i18n.t('solutions.header_edit_solution')
                : this.i18n.t('solutions.header_new_solution');
        }
        return editing.project
            ? this.i18n.t('solutions.header_edit_project')
            : this.i18n.t('solutions.header_new_project', { solution: editing.solution.name });
    });

    saveEditor(): void {
        const editing = this.page.editing();
        if (!editing) return;
        const name = this.page.formName().trim();
        if (!name) {
            this.page.formError.set(this.i18n.t('solutions.name_required'));
            return;
        }
        // Sent as typed, empty included: on a change the server reads an empty description as
        // "clear it", which is what emptying the field means.
        const body = { name, description: this.page.formDescription().trim() };

        const request: Observable<unknown> =
            editing.kind === 'solution'
                ? editing.solution
                    ? this.api.updateSolution(editing.solution.id, body)
                    : this.api.createSolution(body)
                : editing.project
                  ? this.api.updateProject(editing.project.id, body)
                  : this.api.createProject(editing.solution.id, body);

        this.page.saving.set(true);
        this.page.formError.set(null);
        request.subscribe({
            next: () => {
                this.page.saving.set(false);
                this.page.editorVisible.set(false);
                this.page.reload();
            },
            error: (failure) => {
                this.page.saving.set(false);
                // Kept in the dialog: a name already taken is the usual refusal, and closing the
                // dialog to say so would lose what was typed.
                this.page.formError.set(
                    this.nameTaken(failure, editing, name) ?? messageOf(failure, this.i18n.t('solutions.error_save'))
                );
            }
        });
    }

    /**
     * A taken name, read from the 409's type and said in the screen's language — null for any other
     * refusal. The server answers a taken name the same way whether the dialog creates or renames (it
     * used to be a 400 on those and a 409 on a move), so the type is what tells it apart, never the
     * status or the English sentence.
     */
    private nameTaken(failure: unknown, editing: Editing, name: string): string | null {
        const type = problemType(failure);
        if (editing.kind === 'solution' && type === SOLUTION_NAME_TAKEN) {
            return this.i18n.t('solutions.solution_name_taken', { name });
        }
        if (editing.kind === 'project' && type === PROJECT_NAME_TAKEN) {
            return this.i18n.t('solutions.project_name_taken', { solution: editing.solution.name, name });
        }
        return null;
    }
}
