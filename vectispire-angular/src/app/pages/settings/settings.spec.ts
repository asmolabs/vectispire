import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { beforeEach, describe, expect, it } from 'vitest';
import { Settings } from './settings';

/**
 * The settings screen, and the connection test that never appeared.
 *
 * <p>The button was gated on the section's title being `Model review`, while the server sent the
 * enum constant lowercased — `model_review`. The condition could never be true, and nothing said
 * so: no error, no warning, simply a button that was not there. It is now keyed to the settings
 * the section holds, and this suite is what would have caught either version.
 */
describe('the settings screen', () => {
    let fixture: ComponentFixture<Settings>;
    let http: HttpTestingController;

    /** The catalogue as the server sends it: section labels, not enum constants. */
    const CATALOGUE = {
        settings: [
            {
                key: 'ai_review_model',
                section: 'OWASP review',
                label: 'Local model name',
                description: '',
                type: 'text',
                value: 'gemma4:12b-it-qat',
                default: 'gemma4:12b-it-qat',
                sensitivity: 'normal'
            },
            {
                key: 'notification_webhook_url',
                section: 'Notifications',
                label: 'Webhook URL',
                description: '',
                type: 'text',
                value: '',
                default: '',
                sensitivity: 'normal'
            }
        ]
    };

    beforeEach(async () => {
        await TestBed.configureTestingModule({
            imports: [Settings],
            providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        fixture = TestBed.createComponent(Settings);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();

        http.expectOne('/api/v1/settings').flush(CATALOGUE);
        http.expectOne('/api/v1/settings/ticket-token').flush({ configured: false });
        http.expectOne('/api/v1/settings/webhook-secret').flush({ configured: false });
        fixture.detectChanges();
    });

    it('offers the connection test on the section that holds the model settings', () => {
        fixture.componentInstance.activeTab.set('ai');
        fixture.detectChanges();
        const text = fixture.nativeElement.textContent;
        expect(text.includes('Test the connection') || text.includes('settings.test_connection')).toBe(true);
    });

    it('keys the button to the settings, not to the section title', () => {
        // A label is prose and prose gets reworded; keying the button to it made it vanish
        // silently once already. The keys are the contract.
        const modelReview = { settings: [{ key: 'ai_review_model' }] } as never;
        const notifications = { settings: [{ key: 'notification_webhook_url' }] } as never;

        expect(fixture.componentInstance.isModelReview(modelReview)).toBe(true);
        expect(fixture.componentInstance.isModelReview(notifications)).toBe(false);
    });

    it('shows what the host answered, reachable or not', () => {
        fixture.componentInstance.activeTab.set('ai');
        fixture.detectChanges();
        fixture.componentInstance.testOllama();
        http.expectOne({ method: 'POST', url: '/api/v1/settings/ollama-test' }).flush({
            reachable: true,
            modelInstalled: false,
            model: 'gemma4:12b-it-qat',
            url: 'http://localhost:11434',
            models: ['gemma4:26b'],
            detail: 'Reachable, but "gemma4:12b-it-qat" is not installed there.'
        });
        fixture.detectChanges();

        // Reachable without the model is the commonest misconfiguration, and a single green tick
        // would hide it until the first report failed on another screen.
        const text = fixture.nativeElement.textContent;
        expect(text.includes('is not installed there') || text.includes('gemma4:12b-it-qat')).toBe(true);
        expect(fixture.componentInstance.testingOllama()).toBe(false);
    });

    it('keeps no copy of the webhook secret once it is saved', () => {
        fixture.componentInstance.webhookSecretInput = 'a-signing-key';
        fixture.componentInstance.saveWebhookSecret();
        http.expectOne({ method: 'PUT', url: '/api/v1/settings/webhook-secret' }).flush({ configured: true });
        fixture.detectChanges();

        // The server never sends it back, so the field is the only place it could still be read —
        // and anyone who reads it can sign a message Vectispire did not send.
        expect(fixture.componentInstance.webhookSecretInput).toBe('');
        expect(fixture.componentInstance.webhookSecretConfigured()).toBe(true);
    });

    it('treats a failed check as an answer about the configuration', () => {
        fixture.componentInstance.testOllama();
        http.expectOne({ method: 'POST', url: '/api/v1/settings/ollama-test' })
            .flush(null, { status: 500, statusText: 'Server Error' });
        fixture.detectChanges();

        expect(fixture.componentInstance.ollama()?.reachable).toBe(false);
        expect(fixture.componentInstance.testingOllama()).toBe(false);
    });
});
