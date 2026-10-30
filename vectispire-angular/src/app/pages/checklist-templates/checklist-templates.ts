import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { MessageModule } from '@openng/optimus-ui/message';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { TemplateImport } from './template-import';
import { TemplateList } from './template-list';
import { TemplatesPage } from './templates-page';
import { TemplateVersionPanel } from './template-version-panel';

/**
 * The organisation's checklist templates (decision 0032 §3, §4, §8).
 *
 * Reading is governance, the auditor included; every write is a security lead's (platform governor,
 * administrator, CISO), and a reader who may not write is shown no write control at all rather than
 * controls the server would refuse. With four-eyes on, the server refuses an author of a draft as its
 * publisher, so an author is shown the publish button disabled and who may publish instead. A 409 is
 * explained from the cause its problem type names, never from its English.
 *
 * The screen is the frame: what it shows is `TemplatesPage`, provided here so each visit starts from
 * nothing, and the import, the list and the version panel are components reading it.
 */
@Component({
    selector: 'app-checklist-templates',
    imports: [MessageModule, TranslatePipe, TemplateImport, TemplateList, TemplateVersionPanel],
    providers: [TemplatesPage],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './checklist-templates.html'
})
export class ChecklistTemplates {
    protected readonly page = inject(TemplatesPage);
}
