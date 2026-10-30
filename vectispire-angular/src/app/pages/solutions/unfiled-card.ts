import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { RouterLink } from '@angular/router';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { TagModule } from '@openng/optimus-ui/tag';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { OpenIssueBadges } from './open-issue-badges';
import { SolutionsPage } from './solutions-page';

/**
 * "No project", always, and always last — empty included. A filing that is not finished has to look
 * unfinished, and a group that disappeared when empty would read as "everything is filed" exactly when
 * the tree failed to say anything.
 */
@Component({
    selector: 'app-unfiled-card',
    imports: [RouterLink, ButtonModule, CardModule, TagModule, TranslatePipe, OpenIssueBadges],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './unfiled-card.html'
})
export class UnfiledCard {
    protected readonly page = inject(SolutionsPage);
}
