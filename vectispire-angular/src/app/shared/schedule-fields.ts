import { Component, computed, inject, input, model, ChangeDetectionStrategy } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { InputNumberModule } from '@openng/optimus-ui/inputnumber';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { ToggleSwitchModule } from '@openng/optimus-ui/toggleswitch';
import { TranslatePipe } from '../core/i18n/translate.pipe';
import { I18nService } from '../core/i18n/i18n.service';
import type { ScheduleInForce } from '../core/api.models';

export type { ScheduleInForce };

/**
 * A number of minutes in the unit a person would say it in: "weekly", "every 6 h", "every 90 min".
 *
 * The default is a number of days and a custom interval a number of minutes; "every 10080 min" is
 * correct and tells nobody that the target runs weekly.
 */
export function cadence(minutes: number, i18n: I18nService): string {
    const WEEK = 7 * 24 * 60;
    const DAY = 24 * 60;
    if (minutes === WEEK) return i18n.t('schedule.weekly');
    if (minutes === DAY) return i18n.t('schedule.daily');
    if (minutes % WEEK === 0) return i18n.t('schedule.every_weeks', { n: minutes / WEEK });
    if (minutes % DAY === 0) return i18n.t('schedule.every_days', { n: minutes / DAY });
    if (minutes % 60 === 0) return i18n.t('schedule.every_hours', { n: minutes / 60 });
    return i18n.t('schedule.every_minutes', { n: minutes });
}

/**
 * A target's schedule in words, for the lists — **the server's answer, not a copy of its rule.**
 *
 * The lists used to work the precedence out here, from the interval and the expression, and that
 * copy said "manual only" of every target without a schedule on the day the server started scanning
 * them weekly (0.11.0). The server now sends `schedule`, the mode in force and the interval it runs
 * at — the installation's default included, which nothing on the row can tell — and this only says
 * it. "Manual only" is spelled out rather than left blank: an empty schedule column reads as
 * "nothing to say here", which is exactly the wrong reading.
 */
export function scheduleLabel(
    target: { scanCron: string | null; schedule?: ScheduleInForce | null },
    i18n: I18nService
): string {
    const schedule = target.schedule;
    switch (schedule?.mode) {
        case 'cron':
            return i18n.t('schedule.label_cron', { cron: target.scanCron?.trim() ?? '' });
        case 'interval':
            return schedule.intervalMinutes ? cadence(schedule.intervalMinutes, i18n) : i18n.t('schedule.label_manual');
        case 'default':
            return schedule.intervalMinutes
                ? i18n.t('schedule.label_default', { every: cadence(schedule.intervalMinutes, i18n) })
                : i18n.t('schedule.label_no_default');
        default:
            return i18n.t('schedule.label_manual');
    }
}

/**
 * The rescan schedule, for a repository or an image alike: the installation's default, an interval,
 * a cron expression, or manual only.
 *
 * Extracted rather than copied into both dialogs because what it carries is a **precedence rule**,
 * and two copies of a rule are two chances to state it differently. The server's is in `Schedules`:
 * manual only wins over everything; then the cron expression, because an interval is counted from
 * the last round and therefore drifts a few minutes each time — a scan configured for the quiet
 * hours ends up running in the middle of the day, which for a job that pulls whole registries is not
 * a detail; then the interval; and with neither, the default.
 *
 * The screen says which is in force instead of leaving somebody to set both and wonder. Two empty
 * fields are no longer "nothing scheduled" but the default, and the dialog says how often that is;
 * "never rescan this" is a switch of its own, since an empty field cannot say it any more.
 */
@Component({
    selector: 'app-schedule-fields',
    imports: [FormsModule, InputNumberModule, InputTextModule, MessageModule, ToggleSwitchModule, TranslatePipe],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './schedule-fields.html'
})
export class ScheduleFields {
    private readonly i18n = inject(I18nService);

    /** Minutes between rescans, or `null` for none. `p-inputnumber` yields `null` when cleared. */
    readonly interval = model<number | null>(null);

    /** A five-field cron expression, or the empty string for none. */
    readonly cron = model<string>('');

    /** "Never rescan this", whatever the default — the one choice two empty fields cannot express. */
    readonly manualOnly = model<boolean>(false);

    /**
     * The installation's default interval, in minutes, so the dialog can say how often "nothing set"
     * runs. Zero is "no default"; `null` is "not known here" — the dialog then names the setting
     * rather than a number it would have to guess.
     */
    readonly defaultMinutes = input<number | null>(null);

    /** Distinguishes the field's own id from its twin's when both dialogs live in one page. */
    readonly idPrefix = model<string>('schedule');

    readonly cronWins = computed(
        () => !this.manualOnly() && this.cron().trim().length > 0 && (this.interval() ?? 0) > 0
    );

    /** Neither field set and not manual only: the installation's default is in force. */
    readonly onDefault = computed(
        () => !this.manualOnly() && this.cron().trim().length === 0 && (this.interval() ?? 0) <= 0
    );

    /** The default in words; reads `translations()` so it redraws when the reader changes language. */
    readonly defaultCadence = computed(() => {
        this.i18n.translations();
        const minutes = this.defaultMinutes();
        return minutes ? cadence(minutes, this.i18n) : '';
    });

    /**
     * Switching manual only on empties both fields, as the server does: a row holding an expression
     * the scheduler ignores tells whoever reads it the wrong thing.
     */
    setManualOnly(on: boolean): void {
        this.manualOnly.set(on);
        if (on) {
            this.interval.set(null);
            this.cron.set('');
        }
    }
}
