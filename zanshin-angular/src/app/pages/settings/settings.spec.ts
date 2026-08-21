import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
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
                key: 'ai_review_enabled',
                section: 'OWASP review',
                label: 'Review the code with a local model',
                description: '',
                type: 'boolean',
                value: 'true',
                default: 'false',
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
            providers: [provideHttpClient(), provideHttpClientTesting()]
        }).compileComponents();

        fixture = TestBed.createComponent(Settings);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();

        http.expectOne('/api/v1/settings').flush(CATALOGUE);
        http.expectOne('/api/v1/settings/ticket-token').flush({ configured: false });
        fixture.detectChanges();
    });

    it('offers the connection test on the section that holds the model settings', () => {
        expect(fixture.nativeElement.textContent).toContain('Test the connection');
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
        expect(fixture.nativeElement.textContent).toContain('is not installed there');
        expect(fixture.componentInstance.testingOllama()).toBe(false);
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
