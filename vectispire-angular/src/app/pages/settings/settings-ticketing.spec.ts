import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { asSchema } from '@/app/core/testing/contract';
import { useEnglish, useFrench } from '@/app/core/testing/english';
import { Settings } from './settings';

/**
 * The tracker cards of the Integrations tab, as an operator wires a tracker: the token Vectispire
 * calls it with, the secret it calls back with, and the webhook addresses to give it. The token's
 * expiry and refusal have their own suite (`settings-ticket-token.spec.ts`); this one is the cards'
 * saves, read through the page, whose banners are where a save is reported.
 */
describe('the tracker cards of the settings page', () => {
    let fixture: ComponentFixture<Settings>;
    let http: HttpTestingController;

    const CATALOGUE = asSchema('Catalog', {
        settings: [
            {
                key: 'ticket_base_url',
                section: 'Ticket tracker',
                label: 'Tracker URL',
                type: 'text',
                value: 'https://tracker.example.com',
                default: '',
                configured: true,
                governor_only: false,
                administrator_only: false
            }
        ]
    });

    function answerReads(): void {
        http.match({ method: 'GET', url: '/api/v1/settings' }).forEach((call) =>
            call.flush(structuredClone(CATALOGUE))
        );
        http.match({ method: 'GET', url: '/api/v1/settings/ticket-token' }).forEach((call) =>
            call.flush(asSchema('TicketTokenState', { configured: false, expirySource: 'unknown' }))
        );
        for (const url of ['webhook-secret', 'ticket-webhook-secret']) {
            http.match({ method: 'GET', url: `/api/v1/settings/${url}` }).forEach((call) =>
                call.flush({ configured: false })
            );
        }
        // The SIEM card reads its own configuration; with none, it offers an empty form.
        http.match({ method: 'GET' }).forEach((call) => call.flush(null, { status: 404, statusText: 'Not Found' }));
        fixture.detectChanges();
    }

    beforeEach(async () => {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [Settings],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();
        useEnglish();
        http = TestBed.inject(HttpTestingController);
        fixture = TestBed.createComponent(Settings);
        fixture.detectChanges();
        answerReads();
    });

    // The clipboard is replaced on the navigator itself by the copy case; put back what was there.
    const clipboard = Object.getOwnPropertyDescriptor(navigator, 'clipboard');
    afterEach(() => {
        if (clipboard) Object.defineProperty(navigator, 'clipboard', clipboard);
        else Reflect.deleteProperty(navigator, 'clipboard');
    });

    const page = (): HTMLElement => fixture.nativeElement as HTMLElement;
    const text = (): string => page().textContent.replace(/\s+/g, ' ');

    function button(label: string): HTMLButtonElement {
        const found = [...page().querySelectorAll('button')].find(
            (candidate) => candidate.textContent.trim() === label
        );
        expect(found, `a button labelled ${label}`).toBeDefined();
        return found!;
    }

    async function integrations(): Promise<void> {
        button('Integrations & SIEM').click();
        fixture.detectChanges();
        answerReads();
        await fixture.whenStable();
    }

    /** Types into a write-only field and presses the Save beside it. */
    async function save(id: string, value: string): Promise<void> {
        const input = page().querySelector(`#${id}`) as HTMLInputElement;
        input.value = value;
        input.dispatchEvent(new Event('input'));
        fixture.detectChanges();
        await fixture.whenStable();
        (input.parentElement!.querySelector('p-button button') as HTMLButtonElement).click();
    }

    it('shows the cards on the Integrations tab only', async () => {
        expect(page().querySelector('#ticket-token')).toBeNull();

        await integrations();

        expect(page().querySelector('#ticket-token')).not.toBeNull();
        expect(text()).toContain('Ticket tracker token');
    });

    it('saves the token through its own route, says it is saved and keeps no copy of it', async () => {
        await integrations();
        expect(text()).toContain('Token — none');

        await save('ticket-token', 'a-tracker-token');
        const put = http.expectOne({ method: 'PUT', url: '/api/v1/settings/ticket-token' });
        expect(put.request.body).toEqual({ token: 'a-tracker-token' });
        put.flush(asSchema('TicketTokenState', { configured: true, expirySource: 'unknown' }));
        fixture.detectChanges();
        await fixture.whenStable();

        expect(text()).toContain('Token — saved');
        expect(text()).toContain('Settings saved.');
        expect((page().querySelector('#ticket-token') as HTMLInputElement).value).toBe('');
    });

    it("shows the server's reason when the tracker token is refused", async () => {
        await integrations();

        await save('ticket-token', 'a-tracker-token');
        http.expectOne({ method: 'PUT', url: '/api/v1/settings/ticket-token' }).flush(
            { title: 'Bad Request', status: 400, detail: 'The tracker answered 401 to this token.' },
            { status: 400, statusText: 'Bad Request' }
        );
        fixture.detectChanges();

        expect(page().querySelector('.p-message-error')?.textContent).toContain(
            'The tracker answered 401 to this token.'
        );
        expect(text()).toContain('Token — none');
    });

    it('saves the inbound webhook secret through its own route', async () => {
        await integrations();

        await save('ticket-webhook-secret', 'a-shared-secret');
        const put = http.expectOne({ method: 'PUT', url: '/api/v1/settings/ticket-webhook-secret' });
        expect(put.request.body).toEqual({ secret: 'a-shared-secret' });
        put.flush({ configured: true });
        fixture.detectChanges();
        await fixture.whenStable();

        expect(text()).toContain('Inbound webhook secret — stored');
        expect((page().querySelector('#ticket-webhook-secret') as HTMLInputElement).value).toBe('');
    });

    it('gives each tracker the address of its webhook on this host, and copies it', async () => {
        const writeText = vi.fn().mockResolvedValue(undefined);
        Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText } });
        await integrations();

        const addresses = [...page().querySelectorAll('code')].map((code) => code.textContent.trim());
        expect(addresses).toEqual(
            ['jira', 'gitlab', 'github', 'servicenow'].map(
                (tracker) => `${window.location.origin}/api/v1/tickets/webhook/${tracker}`
            )
        );

        const copies = [...page().querySelectorAll('button')].filter(
            (one) => one.textContent.trim() === 'Copy the URL'
        );
        expect(copies).toHaveLength(4);
        copies[2].click();
        await fixture.whenStable();
        fixture.detectChanges();

        expect(writeText).toHaveBeenCalledWith(`${window.location.origin}/api/v1/tickets/webhook/github`);
        expect(copies[2].textContent.trim()).toBe('Copied to clipboard');
        expect(copies[0].textContent.trim()).toBe('Copy the URL');
    });

    it('speaks French to a French reader', async () => {
        await integrations();
        useFrench();
        fixture.detectChanges();

        expect(text()).toContain('Jeton du gestionnaire de tickets');
        expect(text()).toContain('Secret du webhook entrant');
        expect(
            [...page().querySelectorAll('button')].filter((one) => one.textContent.trim() === "Copier l'URL")
        ).toHaveLength(4);
    });
});

/**
 * The cards when the stored states cannot be read: a token in place whose state read failed showed
 * "none", which tells the operator it is missing and invites a save over it.
 */
describe('the tracker cards of the settings page, when the stored states cannot be read', () => {
    let fixture: ComponentFixture<Settings>;
    let http: HttpTestingController;

    function answerReads(): void {
        http.match({ method: 'GET', url: '/api/v1/settings' }).forEach((call) =>
            call.flush(asSchema('Catalog', { settings: [] }))
        );
        http.match({ method: 'GET', url: '/api/v1/settings/ticket-token' }).forEach((call) =>
            call.flush(
                { title: 'Service Unavailable', status: 503, detail: 'The token store is locked.' },
                { status: 503, statusText: 'Service Unavailable' }
            )
        );
        for (const url of ['webhook-secret', 'ticket-webhook-secret']) {
            // No body: the screen's own sentence stands in for the server's.
            http.match({ method: 'GET', url: `/api/v1/settings/${url}` }).forEach((call) =>
                call.flush(null, { status: 502, statusText: 'Bad Gateway' })
            );
        }
        http.match({ method: 'GET' }).forEach((call) => call.flush(null, { status: 404, statusText: 'Not Found' }));
        fixture.detectChanges();
    }

    beforeEach(async () => {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [Settings],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();
        useEnglish();
        http = TestBed.inject(HttpTestingController);
        fixture = TestBed.createComponent(Settings);
        fixture.detectChanges();
        answerReads();
        [...(fixture.nativeElement as HTMLElement).querySelectorAll('button')]
            .find((one) => one.textContent.trim() === 'Integrations & SIEM')!
            .click();
        fixture.detectChanges();
        answerReads();
        await fixture.whenStable();
    });

    const page = (): HTMLElement => fixture.nativeElement as HTMLElement;
    const failure = (testId: string): string | undefined =>
        page().querySelector(`[data-testid="${testId}"]`)?.textContent.replace(/\s+/g, ' ').trim();

    it("says each state could not be read, in the server's words when it gave one, never that none is stored", () => {
        expect(failure('ticket-token-state-failed')).toBe('— The token store is locked.');
        expect(failure('ticket-webhook-secret-state-failed')).toBe('— the stored state could not be read');
        expect(failure('webhook-secret-state-failed')).toBe('— the stored state could not be read');
        const text = page().textContent.replace(/\s+/g, ' ');
        expect(text).not.toContain('Token — none');
        expect(text).not.toContain('none stored');
    });
});
