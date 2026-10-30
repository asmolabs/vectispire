import { ChangeDetectionStrategy, Component, computed, inject } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from '@openng/optimus-ui/button';
import { SelectModule } from '@openng/optimus-ui/select';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import { messageOf } from '../../core/api-error';
import { ChecklistsApi } from '../../core/api/checklists.api';
import type { ChecklistChange, ChecklistItemPair, ChecklistPairingChange } from '../../core/api.models';
import { I18nService } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { changeLabel, changeSeverity } from './templates-model';
import { TemplatesPage } from './templates-page';

/**
 * The pairing with the previous published version (decision 0032 §4): each item's fate against it, and
 * on a draft, an added item paired by hand with a removed one — the same line reworded, whose answers a
 * project then carries — or such a pair undone.
 */
@Component({
    selector: 'app-template-pairing',
    imports: [FormsModule, ButtonModule, SelectModule, TableModule, TagModule, TranslatePipe],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './template-pairing.html'
})
export class TemplatePairing {
    private readonly api = inject(ChecklistsApi);
    private readonly i18n = inject(I18nService);
    protected readonly page = inject(TemplatesPage);

    private readonly pairing = computed(() => this.page.preview()?.pairing ?? []);
    protected readonly changes = computed(() =>
        this.pairing().map((change) => ({
            ...change,
            text: changeLabel(this.i18n, change.change),
            tone: changeSeverity(change.change)
        }))
    );
    protected readonly pairingCounts = computed(() => {
        const counts: Record<ChecklistChange, number> = { unchanged: 0, changed: 0, added: 0, removed: 0 };
        for (const change of this.pairing()) counts[change.change] += 1;
        return counts;
    });
    readonly addedOptions = computed(() =>
        this.pairing()
            .filter((change) => change.change === 'added' && change.readKey)
            .map((change) => ({ value: change.readKey!, label: `${change.row ?? '?'} · ${change.control ?? ''}` }))
    );
    readonly removedOptions = computed(() =>
        this.pairing()
            .filter((change) => change.change === 'removed' && change.previousKey)
            .map((change) => ({
                value: change.previousKey!,
                label: `${change.previousRow ?? '?'} · ${change.previousControl ?? ''}`
            }))
    );

    /** The pairs the draft has, plus the one chosen: the route replaces the list whole. */
    protected pair(): void {
        const added = this.page.pairAdded();
        const removed = this.page.pairRemoved();
        if (!added || !removed) return;
        this.sendPairs([...(this.page.version()?.pairs ?? []), { added, removed }]);
    }

    /** A pair made by hand, undone: the list without it. */
    protected unpair(change: ChecklistPairingChange): void {
        this.sendPairs((this.page.version()?.pairs ?? []).filter((pair) => pair.added !== change.readKey));
    }

    private sendPairs(pairs: ChecklistItemPair[]): void {
        const selected = this.page.selected();
        const shown = this.page.shown();
        if (!selected || !shown) return;
        this.page.busy.set(true);
        this.page.panelError.set(null);
        this.page.refusal.set(null);
        this.api.pairChecklistItems(selected.slug, selected.ordinal, shown.revision, pairs).subscribe({
            next: (version) => {
                this.page.busy.set(false);
                this.page.pairAdded.set(null);
                this.page.pairRemoved.set(null);
                this.page.afterWrite(version);
            },
            error: (failure) => {
                this.page.busy.set(false);
                if (!this.page.refuse(failure, 'edit', shown.revision)) {
                    this.page.panelError.set(messageOf(failure, this.i18n.t('checklist_templates.error_pairs')));
                }
            }
        });
    }
}
