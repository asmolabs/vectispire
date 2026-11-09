import { DatePipe } from '@angular/common';
import { afterNextRender, ChangeDetectionStrategy, Component, computed, inject, Injector } from '@angular/core';
import { ButtonModule } from '@openng/optimus-ui/button';
import { MessageModule } from '@openng/optimus-ui/message';
import { ChecklistsApi } from '../../core/api/checklists.api';
import type { AsMeasuredSkipReason, ChecklistAsMeasured, ChecklistShownMeasurement } from '../../core/api.models';
import { I18nService } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { ChecklistPage } from './checklist-page';
import { AS_MEASURED_SKIP_KEYS, AsMeasuredGroup } from './checklist-model';
import { measuredAnswer, oneClickAnswer } from './measurements';

/**
 * Above the lines: whether their measurements are live or frozen — a reader must know whether they move
 * underneath — and the one click for every line that offers it, in one act (decision 0032 §6), with the
 * summary of what that act did and the lines it left for a person.
 */
@Component({
    selector: 'app-checklist-as-measured',
    imports: [DatePipe, ButtonModule, MessageModule, TranslatePipe],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './checklist-as-measured.html'
})
export class ChecklistAsMeasuredPanel {
    private readonly api = inject(ChecklistsApi);
    private readonly i18n = inject(I18nService);
    private readonly injector = inject(Injector);
    protected readonly page = inject(ChecklistPage);

    /**
     * The lines "every measured line" sends: each unanswered line whose own button offers the one click,
     * with the digest of the measurement that button would rest on — `oneClickAnswer`, the button's own
     * test, so the act never names a line the person was not shown as answerable. A not-met line is sent
     * too: the server leaves it for the person's no, and the summary names it.
     */
    readonly asMeasuredOffer = computed<ChecklistShownMeasurement[]>(() => {
        const live = !!this.page.measurements()?.live;
        const answerable = this.page.editable();
        return (this.page.view()?.lines ?? []).flatMap((line) => {
            const measured = this.page.measuredOf(line);
            const found = measured?.measurement;
            return !line.answer && found && oneClickAnswer(measured, live, answerable)
                ? [{ itemId: line.itemId, measurementDigest: found.evidenceDigest }]
                : [];
        });
    });

    /**
     * The summary's groups, against the view as it now is: a line answered since — the no a
     * `needs_comment` line was waiting for — leaves its group, so the summary is a list to work through.
     */
    readonly asMeasuredGroups = computed<(AsMeasuredGroup & { label: string })[]>(() => {
        const summary = this.page.asMeasured();
        if (!summary) return [];
        const answered = new Set(
            (this.page.view()?.lines ?? []).filter((line) => !!line.answer).map((line) => line.itemId)
        );
        return (Object.keys(AS_MEASURED_SKIP_KEYS) as AsMeasuredSkipReason[])
            .map((reason) => ({
                reason,
                lines: summary.skipped
                    .filter((skip) => skip.reason === reason)
                    .filter((skip) =>
                        reason === 'already_answered' ? summary.sent.has(skip.itemId) : !answered.has(skip.itemId)
                    )
                    .map((skip) => ({ itemId: skip.itemId, position: skip.position }))
                    .sort((a, b) => a.position - b.position)
            }))
            .filter((group) => group.lines.length > 0)
            .map((group) => ({
                ...group,
                label: this.i18n.t(AS_MEASURED_SKIP_KEYS[group.reason], {
                    lines: group.lines.map((line) => line.position).join(', '),
                    count: group.lines.length
                })
            }));
    });

    /**
     * The one click for every line that offers it, in one act: the met ones are answered yes, each
     * resting on the measurement its button showed; the rest are named in the summary with why. The
     * lines sent are exactly `asMeasuredOffer`'s — never a line the person was not shown.
     */
    protected answerAllAsMeasured(): void {
        const shown = this.page.summary();
        const lines = this.asMeasuredOffer();
        if (!shown || lines.length === 0) return;
        this.page.answering.set(null);
        this.page.asMeasured.set(null);
        this.page.send(
            this.api.answerChecklistAsMeasured(this.page.id(), shown.revision, lines, shown.edition),
            (result) => result.checklist,
            null,
            (result: ChecklistAsMeasured) =>
                this.page.asMeasured.set({
                    revision: result.checklist.checklist.revision,
                    answered: result.answered.length,
                    sent: new Set(lines.map((line) => line.itemId)),
                    skipped: result.skipped
                })
        );
    }

    /**
     * A line the act left for the person's no: its form opens on no, resting on the measurement, and
     * the comment it needs takes the focus. Should the measurement no longer say not met — read again
     * after the act — the plain form opens instead, and the person reads the line before answering.
     */
    protected answerNoFromSummary(itemId: number): void {
        const line = this.page.view()?.lines.find((one) => one.itemId === itemId);
        if (!line) return;
        if (measuredAnswer(this.page.measuredOf(line)) === 'no') this.page.answerAsMeasured(line);
        else this.page.startAnswer(line);
        afterNextRender(() => document.getElementById(`comment-${itemId}`)?.focus(), { injector: this.injector });
    }
}
