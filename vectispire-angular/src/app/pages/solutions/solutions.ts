import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { MessageModule } from '@openng/optimus-ui/message';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { ConfirmChangeDialog } from './confirm-change-dialog';
import { FileDialog } from './file-dialog';
import { MoveProjectDialog } from './move-project-dialog';
import { NodeEditorDialog } from './node-editor-dialog';
import { PluginsDialog } from './plugins-dialog';
import { SolutionCard } from './solution-card';
import { SolutionsPage } from './solutions-page';
import { UnfiledCard } from './unfiled-card';

export { DESCRIPTION_MAX, NAME_MAX, type Filed } from './solutions-page';

/**
 * Solutions → projects → repositories and container images (decision 0023 and its amendment).
 *
 * **"No project" is always shown, at the end, empty or not.** **Filing is an access change**, and the
 * dialogs say so before the click. The write actions follow `isAdmin`; the server is the authority,
 * and a refusal it sends is shown as it sends it.
 *
 * The screen is the frame: the tree and what each dialog is open on are `SolutionsPage`, provided here
 * so each visit starts from nothing; the solution and project cards, "No project" and the five dialogs
 * are components of their own.
 */
@Component({
    selector: 'app-solutions',
    imports: [
        ButtonModule,
        CardModule,
        MessageModule,
        TranslatePipe,
        ConfirmChangeDialog,
        FileDialog,
        MoveProjectDialog,
        NodeEditorDialog,
        PluginsDialog,
        SolutionCard,
        UnfiledCard
    ],
    providers: [SolutionsPage],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './solutions.html'
})
export class Solutions {
    protected readonly page = inject(SolutionsPage);
}
