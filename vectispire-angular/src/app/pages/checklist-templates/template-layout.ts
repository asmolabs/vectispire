import { ChangeDetectionStrategy, Component, computed, inject } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CheckboxModule } from '@openng/optimus-ui/checkbox';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { TagModule } from '@openng/optimus-ui/tag';
import { messageOf } from '../../core/api-error';
import { ChecklistsApi } from '../../core/api/checklists.api';
import type { ChecklistColumn, ChecklistHeaderField } from '../../core/api.models';
import { I18nService } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import {
    COLUMN_KEYS,
    COLUMNS,
    HEADER_FIELDS,
    HEADER_KEYS,
    layoutOf,
    layoutProblem,
    PROBLEM_KEYS,
    REQUIRED_COLUMNS
} from './templates-model';
import { TemplatesPage } from './templates-page';

/**
 * The layout of the version shown: confirmed or corrected on a draft by a security lead — each column
 * letter, the item rows, the header cells and the template's answer words — and read-only otherwise.
 *
 * A form: the columns no item can be read or answered without, the rows and the words say they are
 * required, and a submit makes the checks the server makes, before anything is sent.
 */
@Component({
    selector: 'app-template-layout',
    imports: [FormsModule, ButtonModule, CheckboxModule, InputTextModule, MessageModule, TagModule, TranslatePipe],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './template-layout.html'
})
export class TemplateLayout {
    private readonly api = inject(ChecklistsApi);
    private readonly i18n = inject(I18nService);
    protected readonly page = inject(TemplatesPage);

    protected readonly columns = COLUMNS;
    protected readonly headerFields = HEADER_FIELDS;
    protected readonly isRequired = Object.fromEntries(
        COLUMNS.map((column) => [column, REQUIRED_COLUMNS.includes(column)])
    ) as Record<ChecklistColumn, boolean>;

    protected readonly columnLabels = computed(
        () =>
            Object.fromEntries(COLUMNS.map((column) => [column, this.i18n.t(COLUMN_KEYS[column])])) as Record<
                ChecklistColumn,
                string
            >
    );
    protected readonly headerLabels = computed(
        () =>
            Object.fromEntries(HEADER_FIELDS.map((field) => [field, this.i18n.t(HEADER_KEYS[field])])) as Record<
                ChecklistHeaderField,
                string
            >
    );
    protected readonly answerValues = computed(() => this.page.preview()?.proposal.answerValues ?? []);

    protected setColumn(column: ChecklistColumn, letters: string): void {
        this.page.layoutDraft.update((draft) =>
            draft ? { ...draft, columns: { ...draft.columns, [column]: letters } } : draft
        );
    }

    protected setHeader(field: ChecklistHeaderField, which: 'label' | 'value', ref: string): void {
        this.page.layoutDraft.update((draft) =>
            draft ? { ...draft, header: { ...draft.header, [field]: { ...draft.header[field], [which]: ref } } } : draft
        );
    }

    protected confirmLayout(): void {
        const draft = this.page.layoutDraft();
        const selected = this.page.selected();
        const shown = this.page.shown();
        if (!draft || !selected || !shown || this.page.busy()) return;
        const problem = layoutProblem(draft);
        if (problem) {
            this.page.formError.set(this.i18n.t(PROBLEM_KEYS[problem]));
            return;
        }
        const hadPairs = (this.page.version()?.pairs.length ?? 0) > 0;
        this.page.formError.set(null);
        this.page.refusal.set(null);
        this.page.busy.set(true);
        this.api.confirmChecklistLayout(selected.slug, selected.ordinal, shown.revision, layoutOf(draft)).subscribe({
            next: (version) => {
                this.page.busy.set(false);
                const count = version.items.length;
                // Each key spelt in its own call, so that the i18n check counts both.
                this.page.notice.set(
                    hadPairs
                        ? this.i18n.t('checklist_templates.layout_confirmed_unpaired', { count })
                        : this.i18n.t('checklist_templates.layout_confirmed', { count })
                );
                this.page.afterWrite(version);
            },
            error: (failure) => {
                this.page.busy.set(false);
                if (!this.page.refuse(failure, 'edit', shown.revision)) {
                    this.page.formError.set(messageOf(failure, this.i18n.t('checklist_templates.error_layout')));
                }
            }
        });
    }
}
