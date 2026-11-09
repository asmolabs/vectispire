import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import type { Observable } from 'rxjs';
import { ButtonModule } from '@openng/optimus-ui/button';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { messageOf } from '../../core/api-error';
import { ChecklistsApi } from '../../core/api/checklists.api';
import type { ChecklistVersion } from '../../core/api.models';
import { I18nService } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { TemplatesPage } from './templates-page';

/**
 * The acts on the version shown: publish or set aside a draft, derive a draft from or retire a
 * published version — each confirmed first. With four-eyes on, an author of the draft is shown the
 * publication greyed out and who may make it instead: the server would refuse them.
 */
@Component({
    selector: 'app-template-acts',
    imports: [FormsModule, ButtonModule, InputTextModule, TranslatePipe],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './template-acts.html'
})
export class TemplateActs {
    private readonly api = inject(ChecklistsApi);
    private readonly i18n = inject(I18nService);
    protected readonly page = inject(TemplatesPage);

    protected readonly deriveLabel = signal('');

    protected derive(): void {
        const selected = this.page.selected();
        if (!selected) return;
        this.page.busy.set(true);
        this.page.panelError.set(null);
        this.page.refusal.set(null);
        this.api.deriveChecklistVersion(selected.slug, selected.ordinal, this.deriveLabel()).subscribe({
            next: (derived) => {
                this.page.busy.set(false);
                this.deriveLabel.set('');
                this.page.notice.set(
                    this.i18n.t('checklist_templates.derived_notice', {
                        ordinal: derived.version.ordinal,
                        from: selected.ordinal
                    })
                );
                this.page.open(derived.templateSlug, derived.version.ordinal);
                this.page.refreshTemplate();
            },
            error: (failure) => {
                this.page.busy.set(false);
                if (!this.page.refuse(failure, 'edit', this.page.shown()?.revision ?? 0)) {
                    this.page.panelError.set(messageOf(failure, this.i18n.t('checklist_templates.error_derive')));
                }
            }
        });
    }

    /**
     * Publishes **the revision on screen** — the one whose cells, layout and pairing the reader has
     * in front of them. Sending the latest revision instead, read afresh, would publish whatever an
     * author changed a second ago: the check the server makes would be defeated by the client.
     */
    protected publish(): void {
        const selected = this.page.selected();
        const shown = this.page.shown();
        if (!selected || !shown) return;
        const revision = shown.revision;
        this.act('publish', this.api.publishChecklistVersion(selected.slug, selected.ordinal, revision), revision);
    }

    protected retire(): void {
        const selected = this.page.selected();
        const shown = this.page.shown();
        if (!selected || !shown) return;
        this.act('retire', this.api.retireChecklistVersion(selected.slug, selected.ordinal), shown.revision);
    }

    private act(act: 'publish' | 'retire', request: Observable<ChecklistVersion>, revision: number): void {
        const wasDraft = this.page.shown()?.status === 'draft';
        this.page.busy.set(true);
        this.page.confirming.set(null);
        this.page.refusal.set(null);
        this.page.panelError.set(null);
        request.subscribe({
            next: (version) => {
                this.page.busy.set(false);
                const ordinal = version.version.ordinal;
                this.page.notice.set(
                    act === 'publish'
                        ? this.i18n.t('checklist_templates.published_notice', { ordinal })
                        : wasDraft
                          ? this.i18n.t('checklist_templates.set_aside_notice', { ordinal })
                          : this.i18n.t('checklist_templates.retired_notice', { ordinal })
                );
                this.page.afterWrite(version);
            },
            error: (failure) => {
                this.page.busy.set(false);
                if (!this.page.refuse(failure, act, revision)) {
                    this.page.panelError.set(messageOf(failure, this.i18n.t('checklist_templates.error_act')));
                }
            }
        });
    }
}
