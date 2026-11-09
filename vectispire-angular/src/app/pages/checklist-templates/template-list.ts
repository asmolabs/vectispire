import { DatePipe } from '@angular/common';
import { ChangeDetectionStrategy, Component, computed, inject } from '@angular/core';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import type { ChecklistTemplate } from '../../core/api.models';
import { I18nService } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { statusLabel, statusSeverity } from './templates-model';
import { TemplatesPage } from './templates-page';

/**
 * The organisation's templates and each one's versions, the one open below marked. A template with a
 * draft offers no new version: the server keeps one draft per template.
 */
@Component({
    selector: 'app-template-list',
    imports: [DatePipe, ButtonModule, CardModule, TableModule, TagModule, TranslatePipe],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './template-list.html'
})
export class TemplateList {
    private readonly i18n = inject(I18nService);
    protected readonly page = inject(TemplatesPage);

    /** Each template with its versions in words, computed once per list, selection or language. */
    protected readonly rows = computed(() => {
        const selected = this.page.selected();
        return this.page.templates().map((template) => ({
            ...template,
            hasDraft: template.versions.some((version) => version.status === 'draft'),
            versions: template.versions.map((version) => ({
                ...version,
                statusText: statusLabel(this.i18n, version.status),
                statusTone: statusSeverity(version.status),
                open: selected?.slug === template.slug && selected.ordinal === version.ordinal
            }))
        }));
    });

    /** Offers the next version of an existing template: the import form, with its slug. */
    protected newVersionOf(template: ChecklistTemplate): void {
        this.page.uploadSlug.set(template.slug);
        this.page.uploadName.set('');
        this.page.uploadError.set(null);
        document.getElementById('checklist-file')?.focus();
    }
}
