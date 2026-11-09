import { ChangeDetectionStrategy, Component, inject, input } from '@angular/core';
import { ButtonModule } from '@openng/optimus-ui/button';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { ChecklistPage } from './checklist-page';
import type { Refusal } from './checklist-model';

/**
 * A refused write, explained: above the checklist when it concerns no single line, on the line when it
 * does. A reload is offered where reloading is the remedy — never for four-eyes, which it cannot cure.
 */
@Component({
    selector: 'app-checklist-refusal',
    imports: [ButtonModule, TranslatePipe],
    changeDetection: ChangeDetectionStrategy.Eager,
    template: `
        <div
            class="mb-4 p-3 rounded-md border flex flex-wrap items-center justify-between gap-3"
            style="border-color: var(--p-orange-400)"
            role="alert"
            data-testid="refusal"
        >
            <span data-testid="refusal-message">{{ refusal().message }}</span>
            @if (refusal().reload) {
                <p-button
                    id="reload-checklist"
                    icon="pi pi-refresh"
                    size="small"
                    [outlined]="true"
                    [label]="'project_checklist.reload_btn' | translate"
                    (onClick)="page.reload()"
                />
            }
        </div>
    `
})
export class ChecklistRefusal {
    protected readonly page = inject(ChecklistPage);
    readonly refusal = input.required<Refusal>();
}
