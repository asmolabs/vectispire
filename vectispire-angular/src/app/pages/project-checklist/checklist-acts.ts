import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { MessageModule } from '@openng/optimus-ui/message';
import { TextareaModule } from '@openng/optimus-ui/textarea';
import { ChecklistsApi } from '../../core/api/checklists.api';
import { I18nService } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { ChecklistPage } from './checklist-page';
import { parseChoice, SignOffBlock, signOffBlockOf } from './checklist-model';
import { changedSinceSubmission } from './measurements';

/**
 * The acts the newest revision's status allows — submit a draft, sign off or return a submitted one,
 * reopen a signed-off one — and the move to another version, offered to those who write.
 *
 * The sign-off is an approver's and, under four-eyes, somebody who wrote none of the revision: the
 * button says why it is greyed out, from the `authors` and `fourEyesRequired` the view carries, and the
 * server has the last word.
 */
@Component({
    selector: 'app-checklist-acts',
    imports: [FormsModule, ButtonModule, CardModule, MessageModule, TextareaModule, TranslatePipe],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './checklist-acts.html'
})
export class ChecklistActs {
    private readonly api = inject(ChecklistsApi);
    private readonly i18n = inject(I18nService);
    protected readonly page = inject(ChecklistPage);

    protected readonly moveChoice = signal<string | null>(null);
    protected readonly returnReason = signal('');
    protected readonly returnError = signal<string | null>(null);

    protected readonly status = computed(() => this.page.summary()?.status ?? null);
    /**
     * The view's own verdict: on a draft its `readyToSubmit` and line problems already count what the
     * submission's measurement would refuse — a yes the measurement contradicts, a yes without data short
     * of its comment or proof — so the measurements route is read to show them, never to decide.
     */
    protected readonly canSubmit = computed(() => !!this.page.view()?.readyToSubmit);
    protected readonly signOffBlock = computed<SignOffBlock | null>(() =>
        signOffBlockOf(this.page.view(), this.page.approves(), this.page.username())
    );
    /** Lines measured otherwise than at the submission: the sign-off would be refused for them. */
    protected readonly changedSinceSubmission = computed(() => changedSinceSubmission(this.page.measurements()));
    /** Every published version but the one the checklist is on: moving to it again is refused. */
    private readonly moveTargets = computed(() => {
        const shown = this.page.summary();
        return this.page
            .offered()
            .filter(
                (version) =>
                    !shown || version.templateSlug !== shown.templateSlug || version.ordinal !== shown.versionOrdinal
            );
    });
    protected readonly moveOptions = computed(() =>
        this.moveTargets().map((version) => this.page.versionOption(version))
    );
    /**
     * Why each listed version no sign-off could fill in cannot be chosen — listed rather than hidden, so that
     * a project on one is not left wondering where its version went, and knows which cells to report.
     */
    protected readonly moveUnrenderable = computed(() => this.page.unrenderableNotes(this.moveTargets()));

    submit(): void {
        const shown = this.page.summary();
        if (!shown) return;
        this.page.write(this.api.submitChecklist(this.page.id(), shown.revision, shown.edition), null, (view) =>
            this.page.notice.set(
                this.i18n.t('project_checklist.submitted_notice', { revision: view.checklist.revision })
            )
        );
    }

    protected startReturn(): void {
        this.page.returning.set(true);
        this.returnReason.set('');
        this.returnError.set(null);
    }

    /** Refused here as the server would: a return names its reason, which a blank one does not. */
    protected confirmReturn(): void {
        const shown = this.page.summary();
        if (!shown) return;
        if (!this.returnReason().trim()) {
            this.returnError.set(this.i18n.t('project_checklist.problem_reason'));
            return;
        }
        this.returnError.set(null);
        this.page.write(
            this.api.returnChecklist(this.page.id(), shown.revision, this.returnReason(), shown.edition),
            null,
            (view) => {
                this.page.returning.set(false);
                this.page.notice.set(
                    this.i18n.t('project_checklist.returned_notice', { revision: view.checklist.revision })
                );
            }
        );
    }

    protected signOff(): void {
        const shown = this.page.summary();
        if (!shown) return;
        this.page.write(this.api.signOffChecklist(this.page.id(), shown.revision, shown.edition), null, (view) =>
            this.page.notice.set(this.i18n.t('project_checklist.signed_notice', { revision: view.checklist.revision }))
        );
    }

    protected reopen(): void {
        const shown = this.page.summary();
        if (!shown) return;
        this.page.write(this.api.reopenChecklist(this.page.id(), shown.revision, shown.edition), null, (view) => {
            this.page.notice.set(
                this.i18n.t('project_checklist.reopened_notice', { revision: view.checklist.revision })
            );
            this.page.refreshRevisions();
        });
    }

    /** A new revision on another version, from the newest one — the edition read on it. */
    protected moveChecklist(): void {
        const choice = parseChoice(this.moveChoice());
        const shown = this.page.summary();
        if (!choice || !shown) return;
        this.page.write(
            this.api.openProjectChecklist(this.page.id(), choice.slug, choice.ordinal, shown.edition),
            null,
            (view) => {
                this.moveChoice.set(null);
                this.page.notice.set(
                    this.i18n.t('project_checklist.moved_notice', {
                        revision: view.checklist.revision,
                        ordinal: view.checklist.versionOrdinal
                    })
                );
                this.page.refreshRevisions();
            }
        );
    }
}
