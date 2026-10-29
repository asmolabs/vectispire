import { ChangeDetectionStrategy, Component, computed, inject, input } from '@angular/core';
import { RouterLink } from '@angular/router';
import { TagModule } from '@openng/optimus-ui/tag';
import type { OpenIssues } from '../../core/api.models';
import { I18nService } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { SolutionsPage } from './solutions-page';

/**
 * The open issues of a node, by severity: one tag per severity that has any, worst first. On a solution
 * or a project each tag opens the list it counts — that severity, that scope, and `unsettled`, because
 * these figures leave settled triage out and a list that kept it would disagree with the number that
 * opened it ("3 high" would open a list of five). "No project" has no such filter, so its tags stay
 * figures.
 */
@Component({
    selector: 'app-open-issue-badges',
    imports: [RouterLink, TagModule, TranslatePipe],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './open-issue-badges.html'
})
export class OpenIssueBadges {
    private readonly i18n = inject(I18nService);
    private readonly page = inject(SolutionsPage);

    readonly issues = input.required<OpenIssues | null | undefined>();
    /** The scope the tags link to; none for "No project". */
    readonly scope = input<{ project_id: number } | { solution_id: number } | null>(null);
    /** The node's name, for the link's accessible name. */
    readonly name = input('');

    protected readonly tags = computed(() => {
        const issues = this.issues();
        if (!issues || (issues.total ?? 0) === 0) return [];
        const scope = this.scope();
        return this.page
            .severities()
            .map((severity) => ({ ...severity, count: issues[severity.field] ?? 0 }))
            .filter((severity) => severity.count > 0)
            .map((severity) => ({
                field: severity.field,
                colour: severity.colour,
                text: `${severity.count} ${severity.label}`,
                link: scope ? { ...scope, severity: severity.field, unsettled: true } : null,
                // "Open the issues of high severity in FinBackoffice / Develop (5)" — the tag alone says "5 High".
                aria: this.i18n.t('solutions.aria_open_issues', {
                    count: severity.count,
                    severity: severity.label.toLocaleLowerCase(this.i18n.currentLang()),
                    name: this.name()
                })
            }));
    });
}
