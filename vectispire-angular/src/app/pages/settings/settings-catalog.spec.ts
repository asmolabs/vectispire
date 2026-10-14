import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { describe, expect, it } from 'vitest';
import { SessionStore } from '@/app/core/session.store';
import { asSchema } from '@/app/core/testing/contract';
import { useEnglish, useFrench } from '@/app/core/testing/english';
import { Settings } from './settings';
import { sessionUser } from '@/app/core/testing/session.fixtures';

/**
 * The server's settings catalogue as the settings page lays it out: one card per section, on the tab
 * the section belongs to, a field per setting — none for a write-only secret or for what the server
 * stamps — and one Save in the page header that sends what changed.
 *
 * Through the page, because the save button and the banners that report it are the page's: the
 * catalogue alone renders fields that nothing sends.
 */
describe('the settings catalogue on the settings page', () => {
    let fixture: ComponentFixture<Settings>;
    let http: HttpTestingController;

    const setting = (
        key: string,
        section: string,
        label: string,
        value: string,
        extra: Record<string, unknown> = {}
    ) => ({
        key,
        section,
        label,
        type: 'text',
        value,
        default: '',
        configured: true,
        governor_only: false,
        administrator_only: false,
        ...extra
    });

    const CATALOGUE = asSchema('Catalog', {
        settings: [
            setting('sla_critical_days', 'Remediation SLAs', 'Critical SLA (days)', '7', { type: 'integer' }),
            setting('retention_scans_days', 'Retention', 'Scan retention (days)', '90', {
                type: 'integer',
                configured: false
            }),
            setting('notification_webhook_url', 'Notifications', 'Webhook URL', 'https://hooks.example.com/a'),
            // Write-only: saved by a route of its own, never offered by the generic form.
            setting('notification_webhook_secret', 'Notifications', 'Webhook secret', ''),
            setting('ai_review_allow_remote_url', 'Model review', 'Allow a remote endpoint', 'false', {
                type: 'boolean'
            }),
            setting('ai_review_ollama_url', 'Model review', 'Endpoint', 'https://llm.example.com'),
            // Stamped by the server, displayed by the model review block, never a field.
            setting('ai_review_risk_acknowledged_by', 'Model review', 'Acknowledged by', ''),
            // A section no tab claims: it has to land somewhere, and that is Governance.
            setting('access_four_eyes', 'Access', 'Four-eyes approval', 'false', {
                type: 'boolean',
                governor_only: true
            })
        ]
    });

    function answerReads(): void {
        http.match({ method: 'GET', url: '/api/v1/settings' }).forEach((call) =>
            call.flush(structuredClone(CATALOGUE))
        );
        for (const url of ['ticket-token', 'webhook-secret', 'ticket-webhook-secret', 'ai-openai-key', 'ticket-ca']) {
            http.match({ method: 'GET', url: `/api/v1/settings/${url}` }).forEach((call) =>
                call.flush({ configured: false, pinned: false, expirySource: 'unknown' })
            );
        }
        http.match({ method: 'GET' }).forEach((call) => call.flush(null, { status: 404, statusText: 'Not Found' }));
        fixture.detectChanges();
    }

    async function open(role = 'SUPERUSER'): Promise<void> {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [Settings],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();
        useEnglish();
        TestBed.inject(SessionStore).open('a-session', sessionUser(role, { username: 'someone' }));
        http = TestBed.inject(HttpTestingController);
        fixture = TestBed.createComponent(Settings);
        fixture.detectChanges();
        answerReads();
        await fixture.whenStable();
        fixture.detectChanges();
    }

    const page = (): HTMLElement => fixture.nativeElement as HTMLElement;
    const text = (): string => page().textContent.replace(/\s+/g, ' ');
    const cardTitles = (): string[] =>
        [...page().querySelectorAll('app-settings-catalog .p-card-title')].map((title) => title.textContent.trim());
    const field = (key: string): HTMLInputElement | null => page().querySelector(`#${key}`);

    function button(label: string): HTMLButtonElement {
        const found = [...document.querySelectorAll('button')].find(
            (candidate) => candidate.textContent.trim() === label
        );
        expect(found, `a button labelled ${label}`).toBeDefined();
        return found!;
    }

    async function tab(label: string): Promise<void> {
        button(label).click();
        fixture.detectChanges();
        answerReads();
        await fixture.whenStable();
        fixture.detectChanges();
    }

    it('lays each section on its tab, under its title, and a section no tab claims under Governance', async () => {
        await open();

        expect(cardTitles()).toEqual(['Remediation SLAs', 'Retention & Purge']);
        expect(page().querySelector('#access_four_eyes')).toBeNull();

        await tab('Governance');
        expect(cardTitles()).toEqual(['Access']);
        expect(page().querySelector('#access_four_eyes')).not.toBeNull();
    });

    it('says which settings were never set, so a default is not read as a decision', async () => {
        await open();

        const retention = field('retention_scans_days')!.closest('.flex-col') as HTMLElement;
        expect(retention.textContent).toContain('Default value — never set.');
        const sla = field('sla_critical_days')!.closest('.flex-col') as HTMLElement;
        expect(sla.textContent).not.toContain('Default value — never set.');
    });

    it('offers no field for a write-only secret, nor for what the server stamps', async () => {
        await open();
        await tab('Integrations & SIEM');
        expect(field('notification_webhook_url')).not.toBeNull();
        expect(field('notification_webhook_secret')).toBeNull();

        await tab('AI');
        expect(field('ai_review_ollama_url')).not.toBeNull();
        expect(field('ai_review_risk_acknowledged_by')).toBeNull();
    });

    it('sends only what changed when the page is saved, and says it was saved', async () => {
        await open();
        await tab('Integrations & SIEM');
        const save = button('Save');
        expect(save.disabled).toBe(true);

        const url = field('notification_webhook_url')!;
        url.value = 'https://hooks.example.com/b';
        url.dispatchEvent(new Event('input'));
        fixture.detectChanges();
        expect(save.disabled).toBe(false);
        save.click();

        const put = http.expectOne({ method: 'PUT', url: '/api/v1/settings' });
        expect(put.request.body).toEqual({ notification_webhook_url: 'https://hooks.example.com/b' });
        put.flush({ updated: 1 });
        answerReads();

        expect(text()).toContain('Settings saved.');
    });

    it("shows the server's reason when a value is refused", async () => {
        await open();
        await tab('Integrations & SIEM');
        const url = field('notification_webhook_url')!;
        url.value = 'ftp://hooks.example.com';
        url.dispatchEvent(new Event('input'));
        fixture.detectChanges();
        button('Save').click();

        http.expectOne({ method: 'PUT', url: '/api/v1/settings' }).flush(
            { title: 'Bad Request', status: 400, detail: 'Webhook URL: expected an https URL.' },
            { status: 400, statusText: 'Bad Request' }
        );
        fixture.detectChanges();

        expect(page().querySelector('.p-message-error')?.textContent).toContain('Webhook URL: expected an https URL.');
        expect(text()).not.toContain('Settings saved.');
    });

    it('greys out a rule this account does not govern, and says why', async () => {
        await open('CISO');
        await tab('Governance');

        const toggle = page().querySelector('#access_four_eyes') as HTMLInputElement;
        expect(toggle.disabled).toBe(true);
        expect(text()).toContain('Only a super-administrator may change this rule.');
    });

    it('asks before opening the public endpoint, and changes nothing until it is accepted', async () => {
        await open();
        await tab('AI');

        (page().querySelector('#ai_review_allow_remote_url') as HTMLInputElement).click();
        fixture.detectChanges();
        await fixture.whenStable();
        expect(document.body.textContent).toContain('Accept the data-leak risk');
        expect(button('Save').disabled).toBe(true);

        button('I accept the risk').click();
        fixture.detectChanges();
        button('Save').click();
        expect(http.expectOne({ method: 'PUT', url: '/api/v1/settings' }).request.body).toEqual({
            ai_review_allow_remote_url: 'true'
        });
    });

    it('speaks French to a French reader', async () => {
        await open();
        useFrench();
        fixture.detectChanges();

        expect(cardTitles()).toEqual(['Délais de remédiation SLA', 'Rétention & Purge des données']);
        expect(text()).toContain('Valeur par défaut — jamais modifiée.');
    });
});
