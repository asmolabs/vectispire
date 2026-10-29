import { ChangeDetectionStrategy, Component, computed, inject, input } from '@angular/core';
import { RouterLink } from '@angular/router';
import { ButtonModule } from '@openng/optimus-ui/button';
import { TagModule } from '@openng/optimus-ui/tag';
import type { ProjectNode, SolutionNode } from '../../core/api.models';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { DetectedLanguages } from '../../shared/detected-languages';
import { OpenIssueBadges } from './open-issue-badges';
import { languagesOf, pathOf, SolutionsPage } from './solutions-page';

/**
 * One project of a solution: its counts, its languages and open issues, its checklist and plugins,
 * what it holds — repositories, then images — and, for an administrator, the moves and the removals.
 */
@Component({
    selector: 'app-project-card',
    imports: [RouterLink, ButtonModule, TagModule, TranslatePipe, DetectedLanguages, OpenIssueBadges],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './project-card.html'
})
export class ProjectCard {
    protected readonly page = inject(SolutionsPage);

    readonly solution = input.required<SolutionNode>();
    readonly project = input.required<ProjectNode>();

    protected readonly languages = computed(() => languagesOf(this.project()));
    protected readonly path = computed(() => pathOf(this.solution(), this.project()));
}
