import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { describe, expect, it } from 'vitest';
import type { SettingDefinition } from '@/app/core/api.models';
import { asSchema } from '@/app/core/testing/contract';
import { secretState, unconfigured } from '@/app/core/testing/settings.fixtures';
import { useEnglish, useFrench } from '@/app/core/testing/english';
import { Settings } from './settings';

/**
 * The top of the AI card, read on the settings page as an operator reads it: whether the code leaves
 * the estate and who accepted that, whether the model answers, and the provider's key — write-only,
 * saved by its own route and forgotten by the page once saved.
 *
 * Through the page rather than the block alone, because the block reports its save and its refusal to
 * the page's banners: a test of the component could not see that a refusal reached the reader.
 */
describe('the model review block of the settings page', () => {
    let fixture: ComponentFixture<Settings>;
    let http: HttpTestingController;

    const setting = (key: string, value: string, extra: Partial<SettingDefinition> = {}): SettingDefinition => ({
        key,
        section: 'Model review',
        label: key,
        type: 'text',
        help: '',
        value,
        default: '',
        configured: true,
        governor_only: false,
        administrator_only: false,
        ...extra
    });

    function catalogue(values: Record<string, string>) {
        return asSchema('Catalog', {
            settings: [
                setting('ai_review_provider', values['ai_review_provider'] ?? 'ollama'),
                setting('ai_review_ollama_url', values['ai_review_ollama_url'] ?? 'http://localhost:11434'),
                setting('ai_review_allow_remote_url', values['ai_review_allow_remote_url'] ?? 'false', {
                    type: 'boolean'
                }),
                setting('ai_review_risk_acknowledged_by', values['ai_review_risk_acknowledged_by'] ?? ''),
                setting('ai_review_risk_acknowledged_at', values['ai_review_risk_acknowledged_at'] ?? '')
            ]
        });
    }

    /** Answers every read the page and its sections make; the ones this suite is not about with nothing. */
    function answerReads(values: Record<string, string>, keyStored: boolean | 'unreadable' = false): void {
        http.match({ method: 'GET', url: '/api/v1/settings' }).forEach((call) => call.flush(catalogue(values)));
        http.match({ method: 'GET', url: '/api/v1/settings/ai-openai-key' }).forEach((call) =>
            keyStored === 'unreadable'
                ? call.flush(
                      { title: 'Service Unavailable', status: 503, detail: 'The key store is locked.' },
                      { status: 503, statusText: 'Service Unavailable' }
                  )
                : call.flush(secretState(keyStored))
        );
        // The other cards' reads, as an install where none of them was set up answers them.
        http.match({ method: 'GET' }).forEach((call) => call.flush(unconfigured(call.request.url)));
        fixture.detectChanges();
    }

    async function open(
        values: Record<string, string> = {},
        keyStored: boolean | 'unreadable' = false
    ): Promise<HTMLElement> {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [Settings],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();
        useEnglish();
        http = TestBed.inject(HttpTestingController);
        fixture = TestBed.createComponent(Settings);
        fixture.detectChanges();
        answerReads(values);

        button('AI').click();
        fixture.detectChanges();
        answerReads(values, keyStored);
        await fixture.whenStable();
        return fixture.nativeElement as HTMLElement;
    }

    const page = (): HTMLElement => fixture.nativeElement as HTMLElement;
    const text = (): string => page().textContent.replace(/\s+/g, ' ');

    function button(label: string): HTMLButtonElement {
        const found = [...page().querySelectorAll('button')].find(
            (candidate) => candidate.textContent.trim() === label
        );
        expect(found, `a button labelled ${label}`).toBeDefined();
        return found!;
    }

    /** The Save beside the key field, not the page's own. */
    const keySave = (): HTMLButtonElement =>
        page().querySelector('#openai-key')!.parentElement!.querySelector('p-button button') as HTMLButtonElement;

    async function typeKey(value: string): Promise<void> {
        const input = page().querySelector('#openai-key') as HTMLInputElement;
        input.value = value;
        input.dispatchEvent(new Event('input'));
        fixture.detectChanges();
        await fixture.whenStable();
    }

    it('warns, above the fields, that the findings leave for a host outside the network, and names it', async () => {
        await open({ ai_review_allow_remote_url: 'true', ai_review_ollama_url: 'https://llm.example.com' });

        const banner = page().querySelector('p-message.p-message-warn, .p-message-warn');
        expect(banner?.textContent).toContain('Risk of data leak');
        expect(banner?.querySelector('strong')?.textContent.trim()).toBe('https://llm.example.com');
    });

    it('says nothing of a leak when the acknowledged endpoint is on the own network', async () => {
        await open({ ai_review_allow_remote_url: 'true', ai_review_ollama_url: 'http://10.0.4.2:11434' });

        expect(text()).not.toContain('Risk of data leak');
    });

    it('shows who accepted the risk and when, as the server recorded it', async () => {
        await open({
            ai_review_allow_remote_url: 'true',
            ai_review_ollama_url: 'https://llm.example.com',
            ai_review_risk_acknowledged_by: 'carol',
            ai_review_risk_acknowledged_at: '2026-10-01T08:30:00Z'
        });

        expect(text()).toContain('Data-leak risk accepted by carol on 01/10/2026 08:30 UTC');
        // Shown, never offered for editing: the name against the decision is the server's to write.
        expect(page().querySelector('#ai_review_risk_acknowledged_by')).toBeNull();
    });

    it('saves the key through its own route, then says it is stored and keeps no copy of it', async () => {
        await open();
        expect(text()).toContain('API key — none stored');

        await typeKey('an-api-key');
        keySave().click();
        const put = http.expectOne({ method: 'PUT', url: '/api/v1/settings/ai-openai-key' });
        expect(put.request.body).toEqual({ secret: 'an-api-key' });
        put.flush(secretState(true));
        fixture.detectChanges();
        await fixture.whenStable();

        expect(text()).toContain('API key — stored');
        expect(text()).toContain('Settings saved.');
        expect((page().querySelector('#openai-key') as HTMLInputElement).value).toBe('');
    });

    it('says the key state could not be read rather than that no key is stored', async () => {
        // A stored key whose state read failed looked absent, and invited a save over it.
        await open({}, 'unreadable');

        expect(page().querySelector('[data-testid="openai-key-state-failed"]')?.textContent).toContain(
            'The key store is locked.'
        );
        expect(text()).not.toContain('none stored');
    });

    it("shows the server's reason when the key is refused", async () => {
        await open();
        await typeKey('an-api-key');
        keySave().click();
        http.expectOne({ method: 'PUT', url: '/api/v1/settings/ai-openai-key' }).flush(
            { title: 'Bad Request', status: 400, detail: 'An API key holds no whitespace.' },
            { status: 400, statusText: 'Bad Request' }
        );
        fixture.detectChanges();

        expect(page().querySelector('.p-message-error')?.textContent).toContain('An API key holds no whitespace.');
        expect(text()).not.toContain('Settings saved.');
    });

    it('reports a connection test that could not run as an answer, in French for a French reader', async () => {
        await open();
        useFrench();
        fixture.detectChanges();

        button('Tester la connexion').click();
        http.expectOne({ method: 'POST', url: '/api/v1/settings/ollama-test' }).flush(null, {
            status: 502,
            statusText: 'Bad Gateway'
        });
        fixture.detectChanges();

        expect(text()).toContain("Le test de connexion n'a pas pu être exécuté.");
        expect(text()).toContain("Clé d'API");
    });
});
