import { ChangeDetectionStrategy, Component, computed, inject } from '@angular/core';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { MessageModule } from '@openng/optimus-ui/message';
import { TagModule } from '@openng/optimus-ui/tag';
import { I18nService } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { TemplateActs } from './template-acts';
import { TemplateItems } from './template-items';
import { TemplateLayout } from './template-layout';
import { TemplatePairing } from './template-pairing';
import { TemplateSheet } from './template-sheet';
import { statusLabel, statusSeverity } from './templates-model';
import { TemplatesPage } from './templates-page';

/**
 * The version open below the list: its summary and the refusal of the last write, then the sheet, the
 * layout, the items, the pairing and the acts — each a component of its own over the page's state.
 */
@Component({
    selector: 'app-template-version-panel',
    imports: [
        ButtonModule,
        CardModule,
        MessageModule,
        TagModule,
        TranslatePipe,
        TemplateActs,
        TemplateItems,
        TemplateLayout,
        TemplatePairing,
        TemplateSheet
    ],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './template-version-panel.html'
})
export class TemplateVersionPanel {
    private readonly i18n = inject(I18nService);
    protected readonly page = inject(TemplatesPage);

    private readonly status = computed(() => this.page.shown()?.status ?? '');
    protected readonly statusText = computed(() => statusLabel(this.i18n, this.status()));
    protected readonly statusTone = computed(() => statusSeverity(this.status()));
}
