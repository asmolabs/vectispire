import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { ButtonModule } from '@openng/optimus-ui/button';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { ScorecardsApi } from '../../core/api/scorecards.api';
import { I18nService } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { ScorecardView } from '../../shared/scorecard';
import { RepositoriesPage } from './repositories-page';

/**
 * A repository's scorecard, and its badge. **A badge exists only if somebody published it**: the screen
 * used to build the badge URL out of the id and show it unconditionally, which is also how anybody could
 * read any repository's grade by counting from one. Published or revoked here, by whoever may.
 */
@Component({
    selector: 'app-scorecard-dialog',
    imports: [ButtonModule, DialogModule, TranslatePipe, ScorecardView],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './scorecard-dialog.html'
})
export class ScorecardDialog {
    private readonly i18n = inject(I18nService);
    private readonly scorecardsApi = inject(ScorecardsApi);
    protected readonly page = inject(RepositoriesPage);

    publishBadge(repoId: number): void {
        this.page.badgeBusy.set(true);
        this.scorecardsApi.publishRepositoryBadge(repoId).subscribe({
            next: (state) => {
                this.page.badge.set(state);
                this.page.badgeBusy.set(false);
            },
            error: () => {
                this.page.badgeBusy.set(false);
                this.page.error.set(this.i18n.t('repositories.badge_publish_failed'));
            }
        });
    }

    revokeBadge(repoId: number): void {
        this.page.badgeBusy.set(true);
        this.scorecardsApi.revokeRepositoryBadge(repoId).subscribe({
            next: (state) => {
                this.page.badge.set(state);
                this.page.copied.set(false);
                this.page.badgeBusy.set(false);
            },
            error: () => {
                this.page.badgeBusy.set(false);
                this.page.error.set(this.i18n.t('repositories.badge_revoke_failed'));
            }
        });
    }

    copyBadgeMarkdown(): void {
        const url = this.page.badge()?.url;
        if (!url) {
            return;
        }
        const markdown = `[![Vectispire Security](${window.location.origin}${url})](${window.location.origin}/repositories)`;
        void navigator.clipboard.writeText(markdown).then(() => {
            this.page.copied.set(true);
            setTimeout(() => this.page.copied.set(false), 3000);
        });
    }
}
