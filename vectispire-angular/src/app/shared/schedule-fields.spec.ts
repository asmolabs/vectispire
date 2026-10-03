import { provideHttpClient, withXhr } from '@angular/common/http';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { beforeEach, describe, expect, it } from 'vitest';
import { I18nService } from '@/app/core/i18n/i18n.service';
import { useEnglish } from '@/app/core/testing/english';
import { ScheduleFields, cadence, scheduleLabel } from './schedule-fields';

/**
 * The schedule, in the dialogs and in the lists (0.11.0).
 *
 * Two empty fields used to mean "never rescanned", and the dialog said so; they now mean the
 * installation's default, and "never" is a switch of its own. What a reader is told about each is
 * the point, so it is asserted through the DOM and the shipped English bundle.
 */
describe('the schedule', () => {
    beforeEach(() => {
        TestBed.configureTestingModule({ imports: [ScheduleFields], providers: [provideHttpClient(withXhr())] });
        useEnglish();
    });

    describe('in the dialog', () => {
        let fixture: ComponentFixture<ScheduleFields>;

        beforeEach(() => {
            fixture = TestBed.createComponent(ScheduleFields);
            fixture.componentRef.setInput('defaultMinutes', 7 * 24 * 60);
            fixture.detectChanges();
        });

        const text = () => (fixture.nativeElement as HTMLElement).textContent ?? '';
        const byTestId = (id: string) => (fixture.nativeElement as HTMLElement).querySelector(`[data-testid="${id}"]`);

        it('says two empty fields are the default, and how often that is', () => {
            expect(byTestId('schedule-default')?.textContent).toContain("the installation's default, weekly");
            expect(byTestId('schedule-manual')).toBeNull();
        });

        it('says so when the installation has no default, rather than naming one', () => {
            fixture.componentRef.setInput('defaultMinutes', 0);
            fixture.detectChanges();

            expect(byTestId('schedule-default')?.textContent).toContain('has no default interval');
        });

        it('names the setting while the default is not known, rather than guessing a number', () => {
            fixture.componentRef.setInput('defaultMinutes', null);
            fixture.detectChanges();

            expect(byTestId('schedule-default')?.textContent).toContain('Settings');
            expect(byTestId('schedule-default')?.textContent).not.toContain('weekly');
        });

        it('stops talking about the default once an interval is set', () => {
            fixture.componentInstance.interval.set(360);
            fixture.detectChanges();

            expect(byTestId('schedule-default')).toBeNull();
        });

        it('switching manual only on empties both fields, locks them, and says what it means', async () => {
            fixture.componentInstance.interval.set(360);
            fixture.componentInstance.cron.set('0 2 * * *');
            fixture.detectChanges();

            const toggle = (fixture.nativeElement as HTMLElement).querySelector<HTMLInputElement>('#schedule-manual');
            expect(toggle).not.toBeNull();
            toggle!.click();
            fixture.detectChanges();
            // `ngModel` applies `disabled` on the next turn.
            await fixture.whenStable();
            fixture.detectChanges();

            expect(fixture.componentInstance.manualOnly()).toBe(true);
            // The server clears them too: a row holding an expression the scheduler ignores misleads.
            expect(fixture.componentInstance.interval()).toBeNull();
            expect(fixture.componentInstance.cron()).toBe('');
            expect(
                (fixture.nativeElement as HTMLElement).querySelector<HTMLInputElement>('#schedule-cron')?.disabled
            ).toBe(true);
            expect(byTestId('schedule-manual')?.textContent).toContain('never by the schedule');
            expect(byTestId('schedule-default')).toBeNull();
        });

        it('still says the expression wins when both are set', () => {
            fixture.componentInstance.interval.set(60);
            fixture.componentInstance.cron.set('0 2 * * *');
            fixture.detectChanges();

            expect(text()).toContain('the cron schedule wins');
        });
    });

    describe('in the lists', () => {
        let i18n: I18nService;

        beforeEach(() => {
            i18n = TestBed.inject(I18nService);
        });

        it("reads the server's answer: the default, a custom interval, a cron expression, manual only", () => {
            expect(scheduleLabel({ scanCron: null, schedule: { mode: 'default', intervalMinutes: 10080 } }, i18n)).toBe(
                'weekly (default)'
            );
            expect(scheduleLabel({ scanCron: null, schedule: { mode: 'interval', intervalMinutes: 360 } }, i18n)).toBe(
                'every 6 h'
            );
            expect(
                scheduleLabel({ scanCron: '0 2 * * *', schedule: { mode: 'cron', intervalMinutes: null } }, i18n)
            ).toBe('cron 0 2 * * *');
            expect(scheduleLabel({ scanCron: null, schedule: { mode: 'manual', intervalMinutes: null } }, i18n)).toBe(
                'manual only'
            );
        });

        it('says a target under no default is not rescanned, rather than calling it the default', () => {
            expect(scheduleLabel({ scanCron: null, schedule: { mode: 'default', intervalMinutes: null } }, i18n)).toBe(
                'not rescanned (no default)'
            );
        });

        it('puts an interval in the unit a person would say it in', () => {
            expect(cadence(1440, i18n)).toBe('daily');
            expect(cadence(3 * 1440, i18n)).toBe('every 3 days');
            expect(cadence(2 * 10080, i18n)).toBe('every 2 weeks');
            expect(cadence(90, i18n)).toBe('every 90 min');
        });
    });
});
