import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { RouterTestingHarness } from '@angular/router/testing';
import { TestBed } from '@angular/core/testing';
import { beforeEach, describe, expect, it } from 'vitest';
import { Settings } from './settings';
import { asSchema } from '@/app/core/testing/contract';
import { useEnglish } from '@/app/core/testing/english';
import { I18nService } from '@/app/core/i18n/i18n.service';
import french from '../../../../public/i18n/fr.json';

/**
 * The default rescan interval on the settings screen (0.11.0).
 *
 * A setting the screen does not show is a setting only an API call can change — three sections once
 * vanished that way, four-eyes among them. This one decides how often every target without a schedule
 * of its own is scanned, so it is found through the router and the DOM, on the tab an administrator
 * would look on.
 */
describe('the settings screen, the default rescan interval', () => {
    let harness: RouterTestingHarness;
    let http: HttpTestingController;

    const CATALOGUE = asSchema('Catalog', {
        settings: [
            {
                key: 'scan_default_interval_days',
                section: 'Scheduling',
                label: 'Default rescan interval (days)',
                help: 'How often a repository or an image is rescanned when it has neither an interval nor a cron expression.',
                type: 'integer',
                value: '7',
                default: '7',
                configured: false,
                governor_only: false,
                administrator_only: false
            }
        ]
    });

    const answerReads = (): void => {
        http.match({ method: 'GET', url: '/api/v1/settings' }).forEach((request) =>
            request.flush(structuredClone(CATALOGUE))
        );
        http.match({ method: 'GET' }).forEach((request) => request.flush({}));
        harness.detectChanges();
    };

    const field = (): HTMLInputElement | null =>
        (harness.routeNativeElement as HTMLElement).querySelector('input#scan_default_interval_days');

    beforeEach(async () => {
        TestBed.configureTestingModule({
            providers: [
                provideHttpClient(withXhr()),
                provideHttpClientTesting(),
                provideRouter([{ path: 'settings', component: Settings }])
            ]
        });
        useEnglish();
        http = TestBed.inject(HttpTestingController);
        harness = await RouterTestingHarness.create();
    });

    it('is on the scanners tab, under its own title, with its value', async () => {
        await harness.navigateByUrl('/settings?tab=scanners');
        answerReads();
        await harness.fixture.whenStable();
        harness.detectChanges();

        const text = (harness.routeNativeElement as HTMLElement).textContent ?? '';
        expect(text).toContain('Scheduling');
        expect(field()).not.toBeNull();
        expect(field()!.value).toBe('7');
    });

    it("is titled in the reader's language, not in the server's English", async () => {
        TestBed.inject(I18nService).translations.set(french);
        await harness.navigateByUrl('/settings?tab=scanners');
        answerReads();

        const text = (harness.routeNativeElement as HTMLElement).textContent ?? '';
        expect(text).toContain('Planification des analyses');
        expect(text).toContain('Intervalle de réanalyse par défaut (jours)');
    });

    it('is not on another tab', async () => {
        await harness.navigateByUrl('/settings?tab=general');
        answerReads();

        expect(field()).toBeNull();
    });
});
