import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { MessageModule } from '@openng/optimus-ui/message';
import { ChecklistsApi } from '../../core/api/checklists.api';
import { I18nService } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { ChecklistPage } from './checklist-page';
import { parseChoice } from './checklist-model';

/** No checklist yet: those who write open one on a published version; the others are told there is none. */
@Component({
    selector: 'app-checklist-opening',
    imports: [FormsModule, ButtonModule, CardModule, MessageModule, TranslatePipe],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './checklist-opening.html'
})
export class ChecklistOpening {
    private readonly api = inject(ChecklistsApi);
    private readonly i18n = inject(I18nService);
    protected readonly page = inject(ChecklistPage);

    protected readonly openChoice = signal<string | null>(null);
    protected readonly openOptions = computed(() =>
        this.page.offered().map((version) => this.page.versionOption(version))
    );
    /** The versions no sign-off could fill in, each with the cells to report: listed, never hidden. */
    protected readonly openUnrenderable = computed(() => this.page.unrenderableNotes(this.page.offered()));

    /**
     * The first checklist of the project, naming the edition the context read — null, since the page
     * offers this only when the context saw no checklist, and the server refuses it when one was
     * opened since.
     */
    protected openChecklist(): void {
        const choice = parseChoice(this.openChoice());
        if (!choice) return;
        const edition = this.page.context()?.latestEdition ?? null;
        this.page.write(
            this.api.openProjectChecklist(this.page.id(), choice.slug, choice.ordinal, edition),
            null,
            (view) => {
                this.openChoice.set(null);
                this.page.notice.set(
                    this.i18n.t('project_checklist.opened_notice', { revision: view.checklist.revision })
                );
                this.page.refreshRevisions();
            }
        );
    }
}
