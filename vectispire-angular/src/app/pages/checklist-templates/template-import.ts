import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { messageOf } from '../../core/api-error';
import { ChecklistsApi, MAX_WORKBOOK_BYTES } from '../../core/api/checklists.api';
import { I18nService } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { conflictOf, REFUSAL_KEYS, SLUG } from './templates-model';
import { TemplatesPage } from './templates-page';

/**
 * A workbook imported as a draft: of a new template, which then needs its name, or as the next version
 * of one that exists. A form: the slug and the file are what it cannot do without, and say so.
 */
@Component({
    selector: 'app-template-import',
    imports: [FormsModule, ButtonModule, CardModule, InputTextModule, MessageModule, TranslatePipe],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './template-import.html'
})
export class TemplateImport {
    private readonly api = inject(ChecklistsApi);
    private readonly i18n = inject(I18nService);
    protected readonly page = inject(TemplatesPage);

    protected readonly uploadLabel = signal('');
    protected readonly uploadFile = signal<File | null>(null);
    protected readonly uploading = signal(false);

    private readonly slug = computed(() => this.page.uploadSlug().trim());
    protected readonly isNewTemplate = computed(() => !this.page.templates().some((one) => one.slug === this.slug()));
    /** A slug typed and not one the server takes: said on the field before the import is offered. */
    protected readonly slugInvalid = computed(() => !!this.slug() && !SLUG.test(this.slug()));
    protected readonly canImport = computed(
        () => SLUG.test(this.slug()) && this.uploadFile() !== null && !this.uploading()
    );

    /**
     * Refused past the route's ceiling before anything is sent, in the sentence the server would
     * answer with — a reader told one thing by the form and another by the server would reasonably
     * wonder which one is right.
     */
    protected pick(event: Event): void {
        const input = event.target as HTMLInputElement;
        const file = input.files?.[0] ?? null;
        this.page.uploadError.set(null);
        if (file && file.size > MAX_WORKBOOK_BYTES) {
            this.uploadFile.set(null);
            input.value = '';
            this.page.uploadError.set(this.i18n.t('checklist_templates.too_large', { limit: MAX_WORKBOOK_BYTES }));
            return;
        }
        this.uploadFile.set(file);
    }

    protected importWorkbook(): void {
        const file = this.uploadFile();
        const slug = this.slug();
        if (!file || !SLUG.test(slug) || this.uploading()) return;
        this.uploading.set(true);
        this.page.uploadError.set(null);
        this.api
            .importChecklistWorkbook(slug, file, {
                name: this.isNewTemplate() ? this.page.uploadName() : null,
                label: this.uploadLabel()
            })
            .subscribe({
                next: (imported) => {
                    this.uploading.set(false);
                    this.uploadFile.set(null);
                    this.uploadLabel.set('');
                    const input = document.getElementById('checklist-file') as HTMLInputElement | null;
                    if (input) input.value = '';
                    this.page.notice.set(
                        this.i18n.t('checklist_templates.imported_notice', {
                            slug: imported.templateSlug,
                            ordinal: imported.version.ordinal
                        })
                    );
                    this.page.reload();
                    this.page.open(imported.templateSlug, imported.version.ordinal);
                },
                error: (failure) => {
                    this.uploading.set(false);
                    // The one cause an import meets, said by the form rather than by a panel that may
                    // show another version.
                    this.page.uploadError.set(
                        conflictOf(failure) === 'has_draft'
                            ? this.i18n.t(REFUSAL_KEYS.has_draft)
                            : messageOf(failure, this.i18n.t('checklist_templates.error_import'))
                    );
                }
            });
    }
}
