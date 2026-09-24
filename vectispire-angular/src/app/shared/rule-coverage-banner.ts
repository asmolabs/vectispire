import { CommonModule } from '@angular/common';
import { Component, computed, inject, signal, ChangeDetectionStrategy } from '@angular/core';
import { RouterLink } from '@angular/router';
import { ButtonModule } from '@openng/optimus-ui/button';
import { RuleSetsApi } from '@/app/core/api/rule-sets.api';
import { TranslatePipe } from '@/app/core/i18n/translate.pipe';
import type { RuleCoverageAssessment } from '@/app/core/api.models';

/**
 * Says when an absence of findings is an absence of looking.
 *
 * **Without it, an instance with no rule for its languages shows "0" in green.** The product
 * ships a single Semgrep rule, in Python — the public sets are not redistributable — so an
 * estate in Java and TypeScript reports zero code findings and reads that as good news. That is
 * the whole difference this component introduces.
 *
 * **It names the consequence, never the setting.** "Code analysis covers a single pattern, in
 * Python" is understood without knowing what a rule set is; "no active set" is understood only
 * by somebody who knows already.
 *
 * **Nothing when coverage is complete.** A warning shown when all is well loses its meaning
 * within days, and then the one that matters becomes invisible too. That is why the `COVERED`
 * state renders nothing at all.
 */
@Component({
    selector: 'zs-rule-coverage-banner',
    standalone: true,
    imports: [CommonModule, ButtonModule, RouterLink, TranslatePipe],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './rule-coverage-banner.html'
})
export class RuleCoverageBanner {
    private readonly ruleSetsApi = inject(RuleSetsApi);

    readonly coverage = signal<RuleCoverageAssessment | null>(null);

    /**
     * Nothing until the answer is there, and nothing if it never arrives.
     *
     * An error banner on a screen that otherwise loaded would say "something is wrong" without
     * saying what, above valid data. The host screen carries its own errors; this one stays
     * quiet.
     */
    readonly visible = computed(() => {
        const state = this.coverage()?.state;
        return state === 'UNCONFIGURED' || state === 'PARTIAL';
    });

    readonly uncovered = computed(() => this.coverage()?.uncovered ?? []);

    constructor() {
        this.ruleSetsApi.ruleCoverage().subscribe({
            next: (data) => this.coverage.set(data),
            error: () => this.coverage.set(null)
        });
    }
}
