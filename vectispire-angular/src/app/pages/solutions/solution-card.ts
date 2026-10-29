import { ChangeDetectionStrategy, Component, inject, input } from '@angular/core';
import { RouterLink } from '@angular/router';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { TagModule } from '@openng/optimus-ui/tag';
import type { SolutionNode } from '../../core/api.models';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { OpenIssueBadges } from './open-issue-badges';
import { ProjectCard } from './project-card';
import { SolutionsPage } from './solutions-page';

/**
 * One solution: its counts and open issues, `partial` said in words when the reader sees part of it,
 * its compliance, and its projects — the one a link from the repository list points at ringed.
 */
@Component({
    selector: 'app-solution-card',
    imports: [RouterLink, ButtonModule, CardModule, TagModule, TranslatePipe, OpenIssueBadges, ProjectCard],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './solution-card.html'
})
export class SolutionCard {
    protected readonly page = inject(SolutionsPage);

    readonly solution = input.required<SolutionNode>();
}
