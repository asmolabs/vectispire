import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { By } from '@angular/platform-browser';
import { beforeEach, describe, expect, it } from 'vitest';
import { Settings } from './settings';
import { SettingsCatalog } from './settings-catalog';
import { SettingsModelReview } from './settings-model-review';
import { SettingsTicketing } from './settings-ticketing';
import { asSchema } from '@/app/core/testing/contract';

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

    /** A section of the page, by its component: each card group is its own component now. */
    const section = <T>(type: new (...args: never[]) => T): T =>
        fixture.debugElement.query(By.directive(type)).componentInstance as T;

    /** The model review block exists only while the AI tab shows the card that holds it. */
    const openModelReview = (): SettingsModelReview => {
        fixture.componentInstance.activeTab.set('ai');
        fixture.detectChanges();
        return section(SettingsModelReview);
    };

    /**
     * The catalogue as the server sends it: section labels, not enum constants.
     *
     * It carried `description` and `sensitivity`, which this document does not declare — two
     * invented fields no screen reads, and which would have made a read silently empty had either
     * ended up in a template.
     */
    const CATALOGUE = asSchema('Catalog', {
            settings: [
                {
                    key: 'ai_review_model',
                    section: 'OWASP review',
                    label: 'Local model name',
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

    beforeEach(async () => {
        await TestBed.configureTestingModule({
            imports: [Settings],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
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

    it('greys out where a credential is sent for an account that may not set the credential', () => {
        // The server refuses the change for anyone but an administrator; an editable field would
        // only turn a deliberate rule into a 403 after the fact. No session here: not an admin.
        const destination = { administrator_only: true, governor_only: false } as never;
        const ordinary = { administrator_only: false, governor_only: false } as never;

        expect(section(SettingsCatalog).isReadOnlyHere(destination)).toBe(true);
        expect(section(SettingsCatalog).isReadOnlyHere(ordinary)).toBe(false);
    });

    it('keys the button to the settings, not to the section title', () => {
        // A label is prose and prose gets reworded; keying the button to it made it vanish
        // silently once already. The keys are the contract.
        const modelReview = { settings: [{ key: 'ai_review_model' }] } as never;
        const notifications = { settings: [{ key: 'notification_webhook_url' }] } as never;

        expect(section(SettingsCatalog).isModelReview(modelReview)).toBe(true);
        expect(section(SettingsCatalog).isModelReview(notifications)).toBe(false);
    });

    it('shows what the host answered, reachable or not', () => {
        const review = openModelReview();
        review.testOllama();
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
        expect(review.testingOllama()).toBe(false);
    });

    it('keeps no copy of the webhook secret once it is saved', () => {
        const ticketing = section(SettingsTicketing);
        ticketing.webhookSecretInput = 'a-signing-key';
        ticketing.saveWebhookSecret();
        http.expectOne({ method: 'PUT', url: '/api/v1/settings/webhook-secret' }).flush({ configured: true });
        fixture.detectChanges();

        // The server never sends it back, so the field is the only place it could still be read —
        // and anyone who reads it can sign a message Vectispire did not send.
        expect(ticketing.webhookSecretInput).toBe('');
        expect(ticketing.webhookSecretConfigured()).toBe(true);
    });

    it('offers a field for the webhook signing secret on the integrations tab, and saves what is typed in it', async () => {
        // The save path existed for a month with no field in front of it: a refactor dropped the
        // card, every test of the component still passed, and the secret could be set only through
        // the API. This one goes through the DOM, which is the level at which that was visible.
        fixture.componentInstance.activeTab.set('integrations');
        fixture.detectChanges();

        const input = fixture.nativeElement.querySelector('input#webhook-secret') as HTMLInputElement | null;
        expect(input).not.toBeNull();
        input!.value = 'a-signing-key';
        input!.dispatchEvent(new Event('input'));
        fixture.detectChanges();
        await fixture.whenStable();

        const card = input!.closest('p-card') as HTMLElement;
        (card.querySelector('p-button button') as HTMLButtonElement).click();

        const put = http.expectOne({ method: 'PUT', url: '/api/v1/settings/webhook-secret' });
        expect(put.request.body).toEqual({ secret: 'a-signing-key' });
        put.flush({ configured: true });
    });

    it('treats a failed check as an answer about the configuration', () => {
        const review = openModelReview();
        review.testOllama();
        http.expectOne({ method: 'POST', url: '/api/v1/settings/ollama-test' })
            .flush(null, { status: 500, statusText: 'Server Error' });
        fixture.detectChanges();

        expect(review.ollama()?.reachable).toBe(false);
        expect(review.testingOllama()).toBe(false);
    });
});
