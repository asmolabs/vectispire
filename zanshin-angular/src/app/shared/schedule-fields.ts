import { Component, computed, model } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { InputNumberModule } from '@openng/optimus-ui/inputnumber';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';

/**
 * A target's schedule in words, for the lists.
 *
 * The same precedence as the form and as the server, said once: a row showing "every 60 min" for
 * a target whose cron expression is what actually runs would be a third opinion on the rule.
 * "Manual only" is spelled out rather than left blank — an empty schedule column reads as
 * "nothing to say here", which is exactly the wrong reading.
 */
export function scheduleLabel(target: { scanIntervalMinutes: number | null; scanCron: string | null }): string {
    if (target.scanCron?.trim()) return `cron ${target.scanCron.trim()}`;
    if ((target.scanIntervalMinutes ?? 0) > 0) return `every ${target.scanIntervalMinutes} min`;
    return 'manual only';
}

/**
 * The rescan schedule, for a repository or an image alike.
 *
 * Extracted rather than copied into both dialogs because what it carries is a **precedence
 * rule**, and two copies of a rule are two chances to state it differently. The server's is in
 * `Schedules`: the cron expression wins, because an interval is counted from the last round and
 * therefore drifts a few minutes each time — a scan configured for the quiet hours ends up
 * running in the middle of the day, which for a job that pulls whole registries is not a detail.
 *
 * The screen says which of the two is in force instead of leaving somebody to set both and
 * wonder. The other half of the same problem is the empty form: an operator reading two blank
 * fields as "the default schedule" would never learn that nothing at all is scheduled, so the
 * empty state is spelled out too.
 */
import { CommonModule } from '@angular/common';
import { TranslatePipe } from '../core/i18n/translate.pipe';

@Component({
    selector: 'app-schedule-fields',
    standalone: true,
    imports: [CommonModule, FormsModule, InputNumberModule, InputTextModule, MessageModule, TranslatePipe],
    templateUrl: './schedule-fields.html'
})
export class ScheduleFields {
    /** Minutes between rescans, or `null` for none. `p-inputnumber` yields `null` when cleared. */
    readonly interval = model<number | null>(null);

    /** A five-field cron expression, or the empty string for none. */
    readonly cron = model<string>('');

    /** Distinguishes the field's own id from its twin's when both dialogs live in one page. */
    readonly idPrefix = model<string>('schedule');

    readonly cronWins = computed(() => this.cron().trim().length > 0 && (this.interval() ?? 0) > 0);

    readonly manualOnly = computed(() => this.cron().trim().length === 0 && (this.interval() ?? 0) <= 0);
}
