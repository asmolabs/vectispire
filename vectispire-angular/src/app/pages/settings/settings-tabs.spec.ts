import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { provideRouter, Router } from '@angular/router';
import { RouterTestingHarness } from '@angular/router/testing';
import { beforeEach, describe, expect, it } from 'vitest';
import { Settings } from './settings';
import { asSchema } from '@/app/core/testing/contract';

/**
 * The AI tab keeps its place and its answers across the actions taken on it.
 *
 * <p>A review reported the model review block snapping back to another tab, or forgetting the
 * connection test, after a save. It did not reproduce — but every case of the settings suite sets
 * `activeTab` on the component, which skips exactly what such a reset would come through: the tab
 * read from the URL, and a catalogue reload redrawing the card that holds the block. These cases go
 * through the router and the DOM, so that a reload which recreated the card (an untracked `@for`, a
 * catalogue emptied while it is fetched again) or a query-parameter read that fell back to
 * `general` fails here rather than on an operator's screen.
 */
describe('the settings screen, on the AI tab', () => {
    let harness: RouterTestingHarness;
    let http: HttpTestingController;
    let root: HTMLElement;

    const CATALOGUE = asSchema('Catalog', {
        settings: [
            {
                key: 'ai_review_model',
                section: 'Model review',
                label: 'Model name',
                type: 'text',
                value: 'gemma4:12b-it-qat',
                default: 'gemma4:12b-it-qat',
                configured: false,
                governor_only: false,
                administrator_only: false
            },
            {
                key: 'notification_webhook_url',
                section: 'Notifications',
                label: 'Webhook URL',
                type: 'text',
                value: '',
                default: '',
                configured: false,
                governor_only: false,
                administrator_only: false
            }
        ]
    });

    const CHECK = asSchema('OllamaCheck', {
        reachable: true,
        modelInstalled: true,
        model: 'gemma4:12b-it-qat',
        url: 'http://localhost:11434',
        models: ['gemma4:12b-it-qat'],
        detail: 'Reachable, and "gemma4:12b-it-qat" is installed.',
        provider: 'ollama',
        remoteAllowed: false
    });

    /**
     * Answers every read the page and its sections make, however many times they were made.
     *
     * <p>The catalogue is a fresh copy each time, as it is off the wire: handing back the same
     * object would leave the signal unchanged, and the reload this suite is about would redraw
     * nothing.
     */
    const answerReads = (): void => {
        http.match({ method: 'GET', url: '/api/v1/settings' }).forEach((request) => request.flush(structuredClone(CATALOGUE)));
        for (const url of ['ticket-token', 'webhook-secret', 'ticket-webhook-secret', 'ai-openai-key']) {
            http.match({ method: 'GET', url: `/api/v1/settings/${url}` }).forEach((request) => request.flush({ configured: false }));
        }
        // The SIEM and threat-feed cards read their own state; their answers do not matter here.
        http.match({ method: 'GET' }).forEach((request) => request.flush({}));
        harness.detectChanges();
    };

    const button = (label: string): HTMLButtonElement => {
        const found = [...root.querySelectorAll('button')].find((candidate) => candidate.textContent?.includes(label));
        expect(found, `a button labelled ${label}`).toBeDefined();
        return found as HTMLButtonElement;
    };

    const onAiTab = (): boolean =>
        TestBed.inject(Router).url === '/settings?tab=ai' && root.querySelector('#openai-key') !== null;

    const checkShown = (): boolean => (root.textContent ?? '').includes(CHECK.detail);

    beforeEach(async () => {
        TestBed.configureTestingModule({
            providers: [
                provideHttpClient(withXhr()),
                provideHttpClientTesting(),
                provideRouter([{ path: 'settings', component: Settings }])
            ]
        });
        http = TestBed.inject(HttpTestingController);
        harness = await RouterTestingHarness.create();
        await harness.navigateByUrl('/settings');
        answerReads();
        root = harness.routeNativeElement as HTMLElement;

        button('settings.tabs.ai').click();
        await harness.fixture.whenStable();
        answerReads();

        button('settings.test_connection').click();
        http.expectOne({ method: 'POST', url: '/api/v1/settings/ollama-test' }).flush(CHECK);
        harness.detectChanges();
        expect(onAiTab()).toBe(true);
        expect(checkShown()).toBe(true);
    });

    it('stays on the tab, with the connection test still answered, after the form is saved and the catalogue reloaded', async () => {
        const model = root.querySelector('input#ai_review_model') as HTMLInputElement;
        model.value = 'gemma4:26b';
        model.dispatchEvent(new Event('input'));
        harness.detectChanges();

        button('settings.save_btn').click();
        const put = http.expectOne({ method: 'PUT', url: '/api/v1/settings' });
        expect(put.request.body).toEqual({ ai_review_model: 'gemma4:26b' });
        put.flush({ updated: 1 });
        // The save re-reads the catalogue and every section's state: this is the reload. The page
        // redraws while the reads are in flight, as it does in a browser — without this, a reload
        // that emptied the catalogue first would be filled again before anything was drawn.
        harness.detectChanges();
        answerReads();
        await harness.fixture.whenStable();

        expect(onAiTab()).toBe(true);
        expect(checkShown()).toBe(true);
    });

    it('stays on the tab, with the connection test still answered, after the API key is saved', async () => {
        const key = root.querySelector('#openai-key') as HTMLInputElement;
        key.value = 'sk-test';
        key.dispatchEvent(new Event('input'));
        harness.detectChanges();

        const saveKey = (key.parentElement as HTMLElement).querySelector('p-button button') as HTMLButtonElement;
        saveKey.click();
        const put = http.expectOne({ method: 'PUT', url: '/api/v1/settings/ai-openai-key' });
        expect(put.request.body).toEqual({ secret: 'sk-test' });
        put.flush({ configured: true });
        await harness.fixture.whenStable();
        harness.detectChanges();

        expect(onAiTab()).toBe(true);
        expect(checkShown()).toBe(true);
        expect(root.textContent).toContain('— stored');
    });

    it('opens on the AI tab when the URL names it', async () => {
        await harness.navigateByUrl('/settings?tab=general');
        answerReads();
        expect(onAiTab()).toBe(false);

        await harness.navigateByUrl('/settings?tab=ai');
        answerReads();
        expect(onAiTab()).toBe(true);
    });
});
