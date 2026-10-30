import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { afterEach, describe, expect, it } from 'vitest';
import type { Integration } from '@/app/core/api.models';
import { SessionStore } from '@/app/core/session.store';
import { missingFromBundles } from '@/app/core/testing/bundles';
import { useEnglish, useFrench } from '@/app/core/testing/english';
import { integration, registry } from '@/app/core/testing/integrations.fixtures';
import { sessionUser } from '@/app/core/testing/session.fixtures';
import {
    INTEGRATION_FAMILY_KEYS,
    INTEGRATION_NAME_KEY_LIST,
    INTEGRATION_SUSPENDS_KEYS
} from '@/app/shared/integrations';
import { Integrations } from './integrations';

/**
 * *Administration → Integrations*, through the DOM.
 *
 * **Who may switch is the first thing a reader of this screen meets**, so every case signs in as one role
 * and reads what the page offers: the platform governor a switch on every row, any other account the state
 * alone. Then what a switch does: off asks first and says what is suspended, on does not ask, and a refusal
 * is shown beside the integration it names, in the words of its cause.
 */
describe('the integrations screen', () => {
    let fixture: ComponentFixture<Integrations>;
    let http: HttpTestingController;

    async function start(role: string, entries: Integration[] = registry()): Promise<void> {
        await TestBed.configureTestingModule({
            imports: [Integrations],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();
        TestBed.inject(SessionStore).open('token', sessionUser(role, { username: 'someone' }));
        useEnglish();
        fixture = TestBed.createComponent(Integrations);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
        http.expectOne({ method: 'GET', url: '/api/v1/integrations' }).flush(entries);
        await settle();
    }

    async function settle(): Promise<void> {
        fixture.detectChanges();
        await fixture.whenStable();
        fixture.detectChanges();
    }

    afterEach(() => http.verify());

    const dom = () => fixture.nativeElement as HTMLElement;
    const text = (selector: string, root: ParentNode = dom()) =>
        root.querySelector(selector)?.textContent?.replace(/\s+/g, ' ').trim() ?? '';
    const row = (key: string) => dom().querySelector<HTMLElement>(`[data-testid="integration-${key}"]`)!;

    async function press(testId: string): Promise<void> {
        const host = document.querySelector<HTMLElement>(`[data-testid="${testId}"]`)!;
        (host.tagName === 'BUTTON' ? host : host.querySelector('button')!).click();
        await settle();
    }

    function refuse(cause: string, key: string, detail: string): void {
        http.expectOne({ method: 'PUT', url: `/api/v1/integrations/${key}/enabled` }).flush(
            {
                type: `urn:vectispire:problem:${cause}`,
                title: 'Conflict',
                status: 409,
                detail,
                instance: `/api/v1/integrations/${key}/enabled`,
                code: cause,
                integration: key
            },
            { status: 409, statusText: 'Conflict' }
        );
    }

    it('groups the integrations by family, in the order of the decision, each with its state', async () => {
        await start('SUPERUSER', registry(['forge.github']));

        const families = Array.from(dom().querySelectorAll('[data-testid^="family-"]')).map((card) =>
            card.getAttribute('data-testid')
        );
        expect(families).toEqual(['family-forge', 'family-siem', 'family-ai', 'family-notification', 'family-tracker']);
        expect(text('[data-testid="family-siem"]')).toContain('SIEM transports');
        expect(text('[data-testid="integration-name"]', row('siem.syslog_tls'))).toBe('Syslog over TLS');
        expect(text('[data-testid="integration-state"]', row('forge.gitlab'))).toBe('Enabled');
        expect(text('[data-testid="integration-state"]', row('forge.github'))).toBe('Disabled');
        expect(text('[data-testid="integration-changed"]', row('forge.gitlab'))).toBe(
            'Never changed since installation'
        );
    });

    it('offers the platform governor a switch on every integration, and says who switched it last', async () => {
        await start('SUPERUSER', registry(['forge.github']));

        expect(dom().querySelectorAll('[data-testid^="switch-off-"]').length).toBe(16);
        expect(dom().querySelectorAll('[data-testid^="switch-on-"]').length).toBe(1);
        expect(row('forge.github').querySelector('[data-testid="switch-on-forge.github"]')).not.toBeNull();
        const changed = text('[data-testid="integration-changed"]', row('forge.github'));
        expect(changed).toContain('by governor');
        expect(changed).toMatch(/\d{2}\/10\/2026 \d{2}:\d{2}/);
        // The accessible name carries the integration, so a screen reader hears which one it switches.
        expect(
            row('forge.github').querySelector('button')?.getAttribute('aria-label') ??
                row('forge.github').querySelector('[aria-label]')?.getAttribute('aria-label')
        ).toBe('Switch on GitHub');
        expect(text('[data-testid="integrations-rule"]')).toContain('deletes nothing');
    });

    for (const role of ['ADMIN', 'CISO', 'AUDITOR', 'USER']) {
        it(`shows ${role} the states and the last change, and no switch`, async () => {
            // The server answers `updatedBy: null` to a reader without a governance role.
            await start(role, [
                integration('forge.gitlab'),
                integration('forge.github', { enabled: false, updatedAt: '2026-10-28T09:15:00Z', updatedBy: null })
            ]);

            expect(dom().querySelector('[data-testid^="switch-"]')).toBeNull();
            expect(dom().querySelectorAll('button').length).toBe(0);
            expect(text('[data-testid="integration-state"]', row('forge.github'))).toBe('Disabled');
            const changed = text('[data-testid="integration-changed"]', row('forge.github'));
            expect(changed).toMatch(/^Last changed on \d{2}\/10\/2026 \d{2}:\d{2}$/);
            expect(text('[data-testid="integrations-rule"]')).toContain('Only the platform governor');
        });
    }

    it('asks before switching off, says what is suspended and that nothing is deleted, and sends on acceptance', async () => {
        await start('SUPERUSER');

        await press('switch-off-forge.gitlab');
        // Nothing sent yet: the dialog stands between the click and the request.
        expect(http.match({ method: 'PUT' }).length).toBe(0);
        expect(text('.p-dialog-title')).toBe('Switch off GitLab?');
        expect(text('[data-testid="confirm-suspends"]', document)).toContain('connections to this forge are suspended');
        expect(text('[data-testid="confirm-kept"]', document)).toBe(
            'Nothing is deleted: switching it back on resumes everything as it was.'
        );

        await press('confirm-switch-off-accept');
        const put = http.expectOne({ method: 'PUT', url: '/api/v1/integrations/forge.gitlab/enabled' });
        expect(put.request.body).toEqual({ enabled: false });
        put.flush(
            integration('forge.gitlab', { enabled: false, updatedAt: '2026-10-30T10:00:00Z', updatedBy: 'someone' })
        );
        await settle();

        expect(text('[data-testid="integration-state"]', row('forge.gitlab'))).toBe('Disabled');
        expect(text('[data-testid="integration-changed"]', row('forge.gitlab'))).toContain('by someone');
        expect(text('[data-testid="integrations-notice"]')).toBe('GitLab is switched off; what uses it is suspended.');
    });

    it('sends nothing when the confirmation is cancelled', async () => {
        await start('SUPERUSER');

        await press('switch-off-tracker.jira');
        expect(text('[data-testid="confirm-suspends"]', document)).toContain('No ticket is opened');
        const cancel = Array.from(document.querySelectorAll<HTMLButtonElement>('.p-dialog-footer button')).find(
            (button) => button.textContent?.includes('Cancel')
        )!;
        cancel.click();
        await settle();

        expect(http.match({ method: 'PUT' }).length).toBe(0);
        expect(document.querySelector('[data-testid="confirm-switch-off"]')).toBeNull();
        expect(text('[data-testid="integration-state"]', row('tracker.jira'))).toBe('Enabled');
    });

    it('switches on without asking: it only resumes', async () => {
        await start('SUPERUSER', registry(['siem.webhook']));

        await press('switch-on-siem.webhook');
        expect(document.querySelector('[data-testid="confirm-switch-off"]')).toBeNull();
        const put = http.expectOne({ method: 'PUT', url: '/api/v1/integrations/siem.webhook/enabled' });
        expect(put.request.body).toEqual({ enabled: true });
        put.flush(integration('siem.webhook', { updatedAt: '2026-10-30T10:00:00Z', updatedBy: 'someone' }));
        await settle();

        expect(text('[data-testid="integration-state"]', row('siem.webhook'))).toBe('Enabled');
        expect(text('[data-testid="integrations-notice"]')).toContain('HTTPS webhook is switched on');
    });

    it('shows a transport in use refused by its cause, beside the integration, naming it', async () => {
        await start('SUPERUSER');

        await press('switch-off-siem.syslog_tls');
        await press('confirm-switch-off-accept');
        refuse(
            'integration-in-use',
            'siem.syslog_tls',
            'The integration "siem.syslog_tls" is in use: the SIEM export sends over it.'
        );
        await settle();

        // The server's own words in English: they say what uses it, which is what has to change.
        const refused = text('[data-testid="integration-refused"]', row('siem.syslog_tls'));
        expect(refused).toBe(
            'Syslog over TLS was not switched off: The integration "siem.syslog_tls" is in use: the SIEM export sends over it.'
        );
        // Beside the one it names, and nowhere else; the state did not move.
        expect(dom().querySelectorAll('[data-testid="integration-refused"]').length).toBe(1);
        expect(text('[data-testid="integration-state"]', row('siem.syslog_tls'))).toBe('Enabled');
    });

    it('switches an AI provider off like any other, saying the AI features stop rather than move elsewhere', async () => {
        await start('SUPERUSER');

        await press('switch-off-ai.openai');
        expect(text('[data-testid="confirm-suspends"]', document)).toContain('AI is unavailable');
        await press('confirm-switch-off-accept');
        http.expectOne({ method: 'PUT', url: '/api/v1/integrations/ai.openai/enabled' }).flush(
            integration('ai.openai', { enabled: false, updatedAt: '2026-10-30T10:00:00Z', updatedBy: 'someone' })
        );
        await settle();

        expect(text('[data-testid="integration-state"]', row('ai.openai'))).toBe('Disabled');
    });

    it('shows a notification channel in use refused by the same cause, with what still uses it, in French too', async () => {
        // Lot I6 answers `integration-in-use` for a channel a setting configures, the uses listed in `detail`.
        await start('SUPERUSER');
        useFrench();
        await settle();

        await press('switch-off-notification.teams');
        await press('confirm-switch-off-accept');
        refuse(
            'integration-in-use',
            'notification.teams',
            'The integration "notification.teams" is in use: notification_teams_url is set.'
        );
        await settle();

        expect(text('[data-testid="integration-refused"]', row('notification.teams'))).toBe(
            "Microsoft Teams n'a pas été désactivée : L'intégration notification.teams est encore utilisée et n'a " +
                "pas été désactivée : modifiez d'abord ce qui l'utilise — le serveur précise : The integration " +
                '"notification.teams" is in use: notification_teams_url is set.'
        );
    });

    it('speaks French for each cause, and reads a cause it does not know as the server wrote it', async () => {
        await start('SUPERUSER', registry(['forge.github']));
        useFrench();
        await settle();

        await press('switch-on-forge.github');
        refuse('integration-disabled', 'forge.github', 'The integration "forge.github" is disabled.');
        await settle();
        expect(text('[data-testid="integration-refused"]', row('forge.github'))).toBe(
            "GitHub n'a pas été activée : L'intégration forge.github est désactivée sur cette installation. Un " +
                'gouverneur de la plateforme la réactive dans Administration → Intégrations ; la même requête réussit alors.'
        );

        await press('switch-on-forge.github');
        refuse('integration-four-eyes', 'forge.github', 'Enabling it waits for a second governor.');
        await settle();
        expect(text('[data-testid="integration-refused"]', row('forge.github'))).toBe(
            "GitHub n'a pas été activée : Enabling it waits for a second governor."
        );
    });

    it('shows an integration and a family this client does not know, as the server sends them', async () => {
        await start('SUPERUSER', [
            integration('forge.bitbucket_cloud', { enabled: false }),
            integration('vault.hashicorp', { enabled: true })
        ]);

        expect(text('[data-testid="integration-name"]', row('forge.bitbucket_cloud'))).toBe('forge.bitbucket_cloud');
        expect(text('[data-testid="family-vault"]')).toContain('vault');
        await press('switch-off-vault.hashicorp');
        // No family sentence to say, the rule alone.
        expect(document.querySelector('[data-testid="confirm-suspends"]')).toBeNull();
        expect(text('[data-testid="confirm-kept"]', document)).toContain('Nothing is deleted');
    });

    it('spells every family, name and suspension in both languages', async () => {
        await start('AUDITOR');
        expect(
            missingFromBundles([
                ...Object.values(INTEGRATION_FAMILY_KEYS),
                ...Object.values(INTEGRATION_SUSPENDS_KEYS),
                ...INTEGRATION_NAME_KEY_LIST
            ])
        ).toEqual([]);
    });
});
