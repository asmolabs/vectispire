import { ChangeDetectionStrategy, Component, computed, input } from '@angular/core';
import { MessageModule } from '@openng/optimus-ui/message';
import { TranslatePipe } from '../core/i18n/translate.pipe';
import type { ScopeCompliance } from '../core/api.models';
import { ComplianceSummaryView } from './compliance-summary';
import { ScorecardView } from './scorecard';

/**
 * A project's or a solution's compliance and score, as the server computed them over the targets the
 * reader sees.
 *
 * **A partial scope says so above its figures**, in the words the tree uses: a score over two of five
 * repositories read without the notice is a score for the product, and it is not one.
 */
@Component({
    selector: 'app-scope-compliance',
    standalone: true,
    imports: [MessageModule, TranslatePipe, ComplianceSummaryView, ScorecardView],
    changeDetection: ChangeDetectionStrategy.Eager,
    template: `
        <div class="flex flex-col gap-4">
            <p class="m-0 text-sm text-muted-color" data-testid="scope-target-count">
                {{ 'scope_compliance.target_count' | translate: { count: scope().targetCount } }}
            </p>
            @if (scope().partial) {
                <p-message severity="warn" [closable]="false" styleClass="w-full" data-testid="scope-partial">{{
                    'scope_compliance.partial' | translate
                }}</p-message>
            }
            <app-scorecard [card]="scope().scorecard" [noData]="nothingObserved()" />
            <app-compliance-summary [summary]="scope().compliance" />
        </div>
    `
})
export class ScopeComplianceView {
    readonly scope = input.required<ScopeCompliance>();

    /** No target of the scope was ever scanned: the score has nothing under it. */
    readonly nothingObserved = computed(() => this.scope().compliance.observedTargets === 0);
}
