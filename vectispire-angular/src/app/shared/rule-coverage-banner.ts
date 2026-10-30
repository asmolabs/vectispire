import { Component, computed, inject, input, signal, ChangeDetectionStrategy } from '@angular/core';
import { RouterLink } from '@angular/router';
import { ButtonModule } from '@openng/optimus-ui/button';
import { RuleSetsApi } from '@/app/core/api/rule-sets.api';
import { TranslatePipe } from '@/app/core/i18n/translate.pipe';
import { keyFor } from '@/app/core/i18n/literal-keys';
import type { OwaspUntaggedReason, RuleCoverageAssessment } from '@/app/core/api.models';

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
    imports: [ButtonModule, RouterLink, TranslatePipe],
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

    /**
     * Whether to say which installed rules declare an OWASP edition the grid does not place — on the rule
     * sets screen, where the answer is to edit or replace the rules, and not on every screen the banner
     * sits on.
     */
    readonly withOwaspTagging = input(false);

    /**
     * The rule files tagged with another OWASP edition only, by reason.
     *
     * **They used to vanish in silence**: the rule runs, its findings reach the backlog without a
     * category, and the grid reads the category it was written for as uncovered with no word of why.
     * Decision 0046 keeps the 2021 edition for 1.0, so the answer is not to map them — it is to say so.
     * A rule declaring no OWASP category at all is not named here: that is most of the upstream corpus,
     * and a warning about it would fire on every instance.
     */
    readonly otherEdition = computed(() =>
        (this.coverage()?.owasp?.untagged ?? []).filter((row) => row.reason !== 'NOT_DECLARED' && row.ruleFiles > 0)
    );

    /** The sentence of each reason; one this client does not know is shown by its name ({@link keyFor}). */
    private static readonly REASON_KEYS: Readonly<Record<OwaspUntaggedReason, string>> = {
        ONLY_2025_EDITION: 'rule_coverage.owasp_other_edition.only_2025',
        ONLY_2017_EDITION: 'rule_coverage.owasp_other_edition.only_2017',
        NOT_DECLARED: 'rule_coverage.owasp_other_edition.not_declared'
    };

    reasonKey(reason: string): string | undefined {
        return keyFor(RuleCoverageBanner.REASON_KEYS, reason);
    }

    readonly otherEditionFiles = computed(() => this.otherEdition().reduce((sum, row) => sum + row.ruleFiles, 0));

    constructor() {
        this.ruleSetsApi.ruleCoverage().subscribe({
            next: (data) => this.coverage.set(data),
            error: () => this.coverage.set(null)
        });
    }
}
