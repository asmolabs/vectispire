import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { Notifications } from './notifications';
import { SessionStore } from '@/app/core/session.store';
import { asSchemaList } from '@/app/core/testing/contract';

/**
 * The notification channels screen. Sending a test posts into somebody's Slack, so the button is a
 * security lead's; and a failed test must say what the server said, since the webhook's own answer
 * — a 404, a revoked token — is the only clue to what to fix in the settings.
 */
describe('the notification channels screen', () => {
    let fixture: ComponentFixture<Notifications>;
    let http: HttpTestingController;

    const CHANNELS = asSchemaList('NotificationChannelStatus', [
        {
            type: 'scan_delta_slack',
            name: 'Slack',
            configured: true,
            destination: 'https://hooks.slack.com/services/T000/B000/…',
            supportedEvents: []
        },
        { type: 'scan_delta_teams', name: 'Teams', configured: false, destination: null, supportedEvents: [] }
    ]);

    async function open(role: string): Promise<void> {
        await TestBed.configureTestingModule({
            imports: [Notifications],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();
        TestBed.inject(SessionStore).open('token', { username: 'x', role, mustChangePassword: false } as never);

        fixture = TestBed.createComponent(Notifications);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
    }

    function list(): void {
        http.expectOne('/api/v1/notifications/channels').flush(CHANNELS);
        fixture.detectChanges();
    }

    const testButtons = () =>
        [...(fixture.nativeElement as HTMLElement).querySelectorAll<HTMLButtonElement>('button')].filter((button) =>
            button.textContent.includes('notifications.test_send')
        );

    describe('for a security lead', () => {
        beforeEach(() => open('CISO'));

        it('lists each channel, with its destination only where one is set', () => {
            list();

            const text = (fixture.nativeElement as HTMLElement).textContent;
            expect(text).toContain('Slack');
            expect(text).toContain('Teams');
            expect(text).toContain('https://hooks.slack.com/services/T000/B000/…');
            expect(text).toContain('notifications.not_set');
        });

        it('offers a test only on a configured channel', () => {
            list();

            expect(testButtons().map((button) => button.disabled)).toEqual([false, true]);
        });

        it('shows what the channel answered to a test', () => {
            list();
            testButtons()[0].click();

            http.expectOne({ method: 'POST', url: '/api/v1/notifications/test/scan_delta_slack' }).flush({
                type: 'scan_delta_slack',
                success: true,
                message: 'Delivered (HTTP 200).',
                testedAt: '2026-10-02T09:00:00Z'
            });
            fixture.detectChanges();

            expect((fixture.nativeElement as HTMLElement).textContent).toContain('Delivered (HTTP 200).');
        });

        it("shows the server's reason when a test fails", () => {
            list();
            testButtons()[0].click();

            http.expectOne({ method: 'POST', url: '/api/v1/notifications/test/scan_delta_slack' }).flush(
                { detail: 'The webhook answered 404: the URL was revoked.' },
                { status: 502, statusText: 'Bad Gateway' }
            );
            fixture.detectChanges();

            expect((fixture.nativeElement as HTMLElement).textContent).toContain(
                'The webhook answered 404: the URL was revoked.'
            );
        });

        it("says, in the server's words, that the channels could not be read", () => {
            http.expectOne('/api/v1/notifications/channels').flush(
                { detail: 'The notification settings could not be decrypted.' },
                { status: 500, statusText: 'Server Error' }
            );
            fixture.detectChanges();

            expect((fixture.nativeElement as HTMLElement).querySelector('p-message')?.textContent).toContain(
                'The notification settings could not be decrypted.'
            );
        });
    });

    it('does not let an ordinary user post a test into a channel', async () => {
        await open('USER');
        list();

        expect(testButtons().map((button) => button.disabled)).toEqual([true, true]);
    });
});
