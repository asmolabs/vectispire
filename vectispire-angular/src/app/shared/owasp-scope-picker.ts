import { Component, computed, inject, input, output, signal, ChangeDetectionStrategy } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { SelectModule } from '@openng/optimus-ui/select';
import { SolutionsApi } from '@/app/core/api/solutions.api';
import type { SolutionTree } from '@/app/core/api.models';
import { I18nService } from '@/app/core/i18n/i18n.service';
import { TranslatePipe } from '@/app/core/i18n/translate.pipe';
import { OwaspScope, scopeOfValue, scopeOptions, scopeValue } from './owasp-scope';

/**
 * The scope picker of the OWASP views: the estate, a solution or a project.
 *
 * One component for both views rather than the same select written twice: the options, their
 * labels and what a value means are the picker's, and the view only says where the scope lives —
 * its URL — and what changing it reloads.
 */
@Component({
    selector: 'zs-owasp-scope-picker',
    imports: [FormsModule, SelectModule, TranslatePipe],
    changeDetection: ChangeDetectionStrategy.Eager,
    // The host is the flex item, as the wrapping div was when the weekly view held the select itself.
    host: { class: 'flex flex-col gap-1' },
    template: `
        <label [for]="inputId()" class="text-sm text-muted-color">{{ 'owasp_weekly.scope' | translate }}</label>
        <p-select
            [inputId]="inputId()"
            [options]="options()"
            optionLabel="label"
            optionValue="value"
            [ngModel]="value()"
            (ngModelChange)="picked($event)"
            [filter]="true"
            filterBy="label"
            styleClass="w-full"
            class="w-full sm:min-w-[20rem]"
        />
    `
})
export class OwaspScopePicker {
    private readonly solutionsApi = inject(SolutionsApi);
    private readonly i18n = inject(I18nService);
    private readonly tree = signal<SolutionTree | null>(null);

    /** The select's id, which the e2e specs and the label reach it by. */
    readonly inputId = input.required<string>();
    readonly scope = input<OwaspScope>(null);
    readonly scopeChange = output<OwaspScope>();

    readonly options = computed(() => {
        this.i18n.translations();
        return scopeOptions(this.i18n, this.tree());
    });

    readonly value = computed(() => scopeValue(this.scope()));

    constructor() {
        // A failure leaves the estate, which is still a view.
        this.solutionsApi.solutionTree().subscribe({ next: (tree) => this.tree.set(tree), error: () => undefined });
    }

    picked(value: string | null): void {
        this.scopeChange.emit(scopeOfValue(value));
    }
}
