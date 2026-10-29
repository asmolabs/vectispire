import { ChangeDetectionStrategy, Component, inject, input } from '@angular/core';
import { FormsModule } from '@angular/forms';
import type { Observable } from 'rxjs';
import { ButtonModule } from '@openng/optimus-ui/button';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { ChecklistsApi, MAX_EVIDENCE_BYTES } from '../../core/api/checklists.api';
import type { ChecklistLine, ChecklistView } from '../../core/api.models';
import { I18nService } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { ChecklistPage } from './checklist-page';
import { DAY, EvidenceDraft, LINK } from './checklist-model';

/**
 * The proof being attached to one line: a link, or a file — which the line may ask for — and the day
 * the work was done. Each field says it is needed; the checks made here are the server's, which makes
 * them again.
 */
@Component({
    selector: 'app-line-proof-form',
    imports: [FormsModule, ButtonModule, InputTextModule, TranslatePipe],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './line-proof-form.html'
})
export class LineProofForm {
    private readonly api = inject(ChecklistsApi);
    private readonly i18n = inject(I18nService);
    protected readonly page = inject(ChecklistPage);

    readonly line = input.required<ChecklistLine>();

    protected setEvidence(patch: Partial<Pick<EvidenceDraft, 'kind' | 'link' | 'performedOn'>>): void {
        this.page.proving.update((draft) => (draft ? { ...draft, ...patch } : draft));
    }

    /**
     * Refused past the route's ceiling before anything is sent, in the sentence the server's body
     * filter answers with — twenty-five megabytes uploaded to be told no is the refusal that costs.
     */
    protected pickEvidence(event: Event): void {
        const input = event.target as HTMLInputElement;
        const file = input.files?.[0] ?? null;
        this.page.evidenceError.set(null);
        if (file && file.size > MAX_EVIDENCE_BYTES) {
            input.value = '';
            this.page.proving.update((draft) => (draft ? { ...draft, file: null } : draft));
            this.page.evidenceError.set(this.i18n.t('project_checklist.too_large', { limit: MAX_EVIDENCE_BYTES }));
            return;
        }
        this.page.proving.update((draft) => (draft ? { ...draft, file } : draft));
    }

    protected save(): void {
        const draft = this.page.proving();
        const shown = this.page.summary();
        const line = this.line();
        if (!draft || !shown || draft.itemId !== line.itemId) return;
        if (!DAY.test(draft.performedOn) || draft.performedOn > this.page.today) {
            this.page.evidenceError.set(this.i18n.t('project_checklist.problem_day'));
            return;
        }
        let request: Observable<ChecklistView>;
        if (draft.kind === 'link') {
            if (!LINK.test(draft.link.trim())) {
                this.page.evidenceError.set(this.i18n.t('project_checklist.problem_link'));
                return;
            }
            request = this.api.attachChecklistLink(
                this.page.id(),
                shown.revision,
                line.itemId,
                draft.link,
                draft.performedOn,
                shown.edition
            );
        } else {
            if (!draft.file) {
                this.page.evidenceError.set(this.i18n.t('project_checklist.problem_file'));
                return;
            }
            request = this.api.attachChecklistFile(
                this.page.id(),
                shown.revision,
                line.itemId,
                draft.file,
                draft.performedOn,
                shown.edition
            );
        }
        this.page.evidenceError.set(null);
        this.page.write(request, line.itemId, () => this.page.proving.set(null));
    }
}
