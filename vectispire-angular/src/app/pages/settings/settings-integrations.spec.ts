import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { describe, expect, it } from 'vitest';
import type { SettingDefinition, SiemConfig, TicketTokenState } from '@/app/core/api.models';
import { SessionStore } from '@/app/core/session.store';
import { asSchema } from '@/app/core/testing/contract';
import { useEnglish } from '@/app/core/testing/english';
import { flushRegistry } from '@/app/core/testing/integrations.fixtures';
import { sessionUser } from '@/app/core/testing/session.fixtures';
import { SIEM_UNCONFIGURED, ticketTokenState, unconfigured } from '@/app/core/testing/settings.fixtures';
import { Settings, type SettingsTab } from './settings';

/**
 * The settings forms against the integrations' registry (decision 0040 §1, §2): an integration the platform
 * governor switched off is not offered for a new choice, and a configuration already on one reads suspended,
 * with the way to *Administration → Integrations*. Through the page and its DOM — the open list of a picker,
 * the options of a select, the state of a field — since a filter right in the component and missing from the
 * template is exactly what a component test passes.
 */
describe('the settings forms, against the switched-off integrations', () => {
    let fixture: ComponentFixture<Settings>;
    let http: HttpTestingController;

    const setting = (key: string, section: string, value: string, extra: Partial<SettingDefinition> = {}) =>
        ({
            key,
            section,
            label: key,
            type: 'text',
            help: '',
            value,
            default: '',
            configured: true,
            governor_only: false,
            administrator_only: false,
            ...extra
        }) as SettingDefinition;

    interface Stored {
        aiProvider?: string;
        tracker?: string;
        webhookUrl?: string;
        slackUrl?: string;
        siem?: SiemConfig;
        token?: TicketTokenState;
    }

    async function open(disabled: string[], stored: Stored = {}, tab: SettingsTab = 'integrations'): Promise<void> {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [Settings],
            providers: [
                provideHttpClient(withXhr()),
                provideHttpClientTesting(),
                provideRouter([{ path: 'settings', component: Settings }])
            ]
        }).compileComponents();
        useEnglish();
        TestBed.inject(SessionStore).open('a-session', sessionUser('SUPERUSER', { username: 'someone' }));
        http = TestBed.inject(HttpTestingController);
        fixture = TestBed.createComponent(Settings);
        fixture.componentInstance.activeTab.set(tab);
        fixture.detectChanges();

        flushRegistry(http, disabled);
        http.match({ method: 'GET', url: '/api/v1/settings' }).forEach((call) =>
            call.flush(
                asSchema('Catalog', {
                    settings: [
                        setting('ai_review_provider', 'Model review', stored.aiProvider ?? 'ollama'),
                        setting('ticket_provider', 'Tickets', stored.tracker ?? 'none'),
                        setting('notification_webhook_url', 'Notifications', stored.webhookUrl ?? ''),
                        setting('notification_slack_url', 'Notifications', stored.slackUrl ?? ''),
                        setting('notification_min_severity', 'Notifications', 'high', { type: 'severity' })
                    ]
                })
            )
        );
        http.match('/api/v1/siem/config').forEach((call) => call.flush(stored.siem ?? SIEM_UNCONFIGURED));
        http.match('/api/v1/settings/ticket-token').forEach((call) => call.flush(stored.token ?? ticketTokenState()));
        for (const url of ['webhook-secret', 'ticket-webhook-secret', 'ai-openai-key', 'ticket-ca']) {
            http.match(`/api/v1/settings/${url}`).forEach((call) => call.flush(unconfigured(call.request.url)));
        }
        http.match({ method: 'GET' }).forEach((call) => call.flush(null, { status: 404, statusText: 'Not Found' }));
        await settle();
    }

    async function settle(): Promise<void> {
        fixture.detectChanges();
        await fixture.whenStable();
        fixture.detectChanges();
    }

    const page = (): HTMLElement => fixture.nativeElement as HTMLElement;
    const text = (selector: string): string =>
        page().querySelector(selector)?.textContent?.replace(/\s+/g, ' ').trim() ?? '';

    /** What a picker offers, read from its open list. */
    async function offered(inputId: string): Promise<string[]> {
        const select = page().querySelector<HTMLElement>(`#${inputId}`)!.closest('p-select')!;
        if (!select.querySelector('[role="listbox"]')) {
            page().querySelector<HTMLElement>(`#${inputId}`)!.click();
            await settle();
        }
        const list = select.querySelector('[role="listbox"]');
        expect(list, 'the picker opened').not.toBeNull();
        return [...list!.querySelectorAll('[role="option"]')].map((option) => option.textContent.trim());
    }

    const siemOptions = (): string[] =>
        [...page().querySelectorAll<HTMLOptionElement>('#siem-protocol option')].map((option) =>
            option.textContent.replace(/\s+/g, ' ').trim()
        );

    describe('the tracker', () => {
        it('offers no tracker the governor switched off for a new choice', async () => {
            await open(['tracker.jira', 'tracker.servicenow']);

            expect(await offered('ticket_provider')).toEqual(['None — no tracker', 'GitLab issues', 'GitHub issues']);
        });

        it('keeps the configured tracker in the list, marked suspended, and links to the integrations screen', async () => {
            await open(['tracker.jira'], {
                tracker: 'jira',
                token: ticketTokenState({ configured: true, state: 'suspended', integration: 'tracker.jira' })
            });

            expect(await offered('ticket_provider')).toEqual([
                'None — no tracker',
                'GitLab issues',
                'GitHub issues',
                'Jira — suspended, integration disabled',
                'ServiceNow'
            ]);
            expect(text('[data-testid="integration-suspended-ticket_provider"]')).toContain(
                'the platform governor switched off tracker.jira'
            );
            const links = [...page().querySelectorAll<HTMLAnchorElement>('a[href="/integrations"]')];
            // One beside the setting, one on the tracker card the token state already marked suspended.
            expect(links.length).toBe(2);
            expect(page().querySelector('[data-testid="tracker-suspended-link"]')?.getAttribute('href')).toBe(
                '/integrations'
            );
        });

        it('says nothing of a tracker the governor left on', async () => {
            await open([], { tracker: 'jira' });

            expect(page().querySelector('[data-testid="integration-suspended-ticket_provider"]')).toBeNull();
            expect(page().querySelector('a[href="/integrations"]')).toBeNull();
        });
    });

    describe('the notification channels', () => {
        it('offers no field for a switched-off channel nobody configured, and says why', async () => {
            await open(['notification.slack']);

            expect(page().querySelector<HTMLInputElement>('#notification_slack_url')!.disabled).toBe(true);
            expect(text('[data-testid="integration-unavailable-notification_slack_url"]')).toBe(
                'Not offered: the platform governor switched off notification.slack. Administration → Integrations'
            );
            // The others stay offered.
            expect(page().querySelector<HTMLInputElement>('#notification_webhook_url')!.disabled).toBe(false);
        });

        it('keeps a configured channel editable, so it can be emptied, and marks it suspended', async () => {
            await open(['notification.webhook'], { webhookUrl: 'https://hooks.example.com/a' });

            expect(page().querySelector<HTMLInputElement>('#notification_webhook_url')!.disabled).toBe(false);
            expect(text('[data-testid="integration-suspended-notification_webhook_url"]')).toContain(
                'Suspended: the platform governor switched off notification.webhook.'
            );
        });
    });

    describe('the SIEM transport', () => {
        it('offers no transport the governor switched off', async () => {
            await open(['siem.syslog_udp', 'siem.syslog_tcp']);

            expect(siemOptions()).toEqual([
                'HTTPS Webhook / Splunk HEC / Sentinel Collector',
                'Syslog (TLS Encrypted)'
            ]);
            expect(page().querySelector('[data-testid="siem-suspended"]')).toBeNull();
        });

        it('keeps the stored transport, marked suspended, and says the events wait', async () => {
            await open(['siem.syslog_tls'], {
                siem: asSchema('SiemConfigResponse', {
                    ...SIEM_UNCONFIGURED,
                    enabled: false,
                    protocol: 'SYSLOG_TLS',
                    endpoint: 'collector.corp:6514'
                })
            });

            expect(siemOptions()).toContain('Syslog (TLS Encrypted) — suspended, integration disabled');
            expect(page().querySelector<HTMLSelectElement>('#siem-protocol')!.value).toBe('SYSLOG_TLS');
            expect(text('[data-testid="siem-suspended"]')).toContain('siem.syslog_tls');
            expect(text('[data-testid="siem-suspended"]')).toContain('wait in the outbox');
            expect(page().querySelector('[data-testid="siem-suspended-link"]')?.getAttribute('href')).toBe(
                '/integrations'
            );
        });
    });

    describe('the AI provider', () => {
        it('offers no provider the governor switched off', async () => {
            await open(['ai.openai'], {}, 'ai');

            expect(await offered('ai_review_provider')).toEqual(['Ollama — a model on a host you run']);
        });

        it('keeps the configured provider, marked suspended', async () => {
            await open(['ai.openai'], { aiProvider: 'openai' }, 'ai');

            expect(await offered('ai_review_provider')).toEqual([
                'Ollama — a model on a host you run',
                'OpenAI-compatible API — suspended, integration disabled'
            ]);
            expect(text('[data-testid="integration-suspended-ai_review_provider"]')).toContain('ai.openai');
        });
    });

    it('offers everything when the registry cannot be read: the server still refuses a disabled one', async () => {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [Settings],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();
        useEnglish();
        TestBed.inject(SessionStore).open('a-session', sessionUser('SUPERUSER'));
        http = TestBed.inject(HttpTestingController);
        fixture = TestBed.createComponent(Settings);
        fixture.componentInstance.activeTab.set('integrations');
        fixture.detectChanges();
        http.match({ method: 'GET' }).forEach((call) => call.flush(null, { status: 500, statusText: 'Server Error' }));
        await settle();

        expect(siemOptions().length).toBe(4);
    });
});
