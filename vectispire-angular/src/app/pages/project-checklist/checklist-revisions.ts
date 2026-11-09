import { DatePipe } from '@angular/common';
import { ChangeDetectionStrategy, Component, computed, inject } from '@angular/core';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import { I18nService } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { ChecklistPage } from './checklist-page';
import { documentSigned, statusLabel, statusSeverity } from './checklist-model';

/**
 * Every revision, newest first: the earlier ones stay readable, never changed, and each one's document
 * can be fetched from its row.
 */
@Component({
    selector: 'app-checklist-revisions',
    imports: [DatePipe, ButtonModule, CardModule, TableModule, TagModule, TranslatePipe],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './checklist-revisions.html'
})
export class ChecklistRevisions {
    private readonly i18n = inject(I18nService);
    protected readonly page = inject(ChecklistPage);

    /** Each row with its status in words, computed once per list or language rather than per pass. */
    protected readonly rows = computed(() =>
        this.page.revisions().map((row) => ({
            ...row,
            statusText: statusLabel(this.i18n, row.status),
            statusTone: statusSeverity(row.status),
            signed: documentSigned(row.status)
        }))
    );
}
