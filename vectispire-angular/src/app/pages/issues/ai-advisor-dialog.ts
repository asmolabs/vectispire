import { ChangeDetectionStrategy, Component, computed, inject, output, signal } from '@angular/core';
import { ButtonModule } from '@openng/optimus-ui/button';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { MessageModule } from '@openng/optimus-ui/message';
import { TagModule } from '@openng/optimus-ui/tag';
import { messageOf } from '../../core/api-error';
import { IntelApi } from '@/app/core/api/intel.api';
import { AiVulnerabilityAdvice, Issue } from '@/app/core/api.models';
import { I18nService } from '@/app/core/i18n/i18n.service';
import * as wording from '@/app/shared/ai-advice';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { IssuesPage } from './issues-page';
import { triageStatusOfVex } from './triage-dialog';

/**
 * The advisor's explanation of one issue, and its VEX suggestion handed to the triage dialog.
 *
 * **The failure is shown.** The message set on an error had no branch in the template: the dialog
 * opened, the spinner stopped, and nothing was left. The message itself promised "local fallback
 * generation" — a fallback this code never wrote. An error that promises what will not happen is worse
 * than a silent one. The page offers the dialog only when a model is configured (`aiEnabled`).
 */
@Component({
    selector: 'app-ai-advisor-dialog',
    imports: [ButtonModule, DialogModule, MessageModule, TagModule, TranslatePipe],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './ai-advisor-dialog.html'
})
export class AiAdvisorDialog {
    private readonly i18n = inject(I18nService);
    private readonly intelApi = inject(IntelApi);
    private readonly page = inject(IssuesPage);

    /** The suggestion is to be applied to this issue: the triage dialog opens on it. */
    readonly apply = output<{ issue: Issue; advice: AiVulnerabilityAdvice }>();

    readonly aiAdviceLoading = signal<boolean>(false);
    readonly aiAdvice = signal<AiVulnerabilityAdvice | null>(null);
    readonly aiAdviceError = signal<string | null>(null);
    /** A signal, so that opening the dialog from code — not only from a click — redraws it. */
    readonly aiModalOpen = signal(false);
    aiTargetIssue: Issue | null = null;

    /**
     * The product's own sentences, in the reader's language, from exactly the values it sent — unknown
     * said as unknown (this formatted a missing EPSS score as 85 %); null when a model wrote them.
     */
    protected readonly words = computed(() => {
        const advice = this.aiAdvice();
        const own = advice?.deterministic;
        if (!advice || !own) return null;
        return {
            summary: wording.adviceSummary(this.i18n, advice.identifier, own),
            exploitation: wording.adviceExploitation(this.i18n, own),
            fix: wording.adviceFix(this.i18n, own)
        };
    });

    /** The advisor's suggestion, as the triage status applying it would choose. */
    protected readonly suggestedLabel = computed(() => {
        const advice = this.aiAdvice();
        return advice ? this.page.triageLabel(triageStatusOfVex(advice.vexSuggestion?.status)) : '';
    });

    openAiAdvisor(issue: Issue): void {
        this.aiTargetIssue = issue;
        this.aiAdvice.set(null);
        this.aiAdviceError.set(null);
        this.aiAdviceLoading.set(true);
        this.aiModalOpen.set(true);

        this.intelApi.explainIssueWithAi(issue.id, this.i18n.currentLang()).subscribe({
            next: (advice) => {
                this.aiAdvice.set(advice);
                this.aiAdviceLoading.set(false);
            },
            error: (response) => {
                this.aiAdviceLoading.set(false);
                this.aiAdviceError.set(messageOf(response, this.i18n.t('issues.ai_unreachable')));
            }
        });
    }

    applySuggestedVex(): void {
        const advice = this.aiAdvice();
        if (!advice || !this.aiTargetIssue) return;
        this.apply.emit({ issue: this.aiTargetIssue, advice });
        this.aiModalOpen.set(false);
    }

    protected copyText(text: string): void {
        if (navigator?.clipboard) {
            void navigator.clipboard.writeText(text);
        }
    }
}
