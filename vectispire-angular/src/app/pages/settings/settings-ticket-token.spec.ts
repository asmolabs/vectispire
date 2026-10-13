import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { beforeEach, describe, expect, it } from 'vitest';
import { asSchema } from '@/app/core/testing/contract';
import { I18nService } from '@/app/core/i18n/i18n.service';
import english from '../../../../public/i18n/en.json';
import french from '../../../../public/i18n/fr.json';
import { SettingsState } from './settings-state';
import { SettingsTicketing } from './settings-ticketing';

/**
 * The tracker token's life on the tracker card, announced as the forge connections' list announces a
 * connection's token: a refusal first, the expiry fourteen days ahead, and "unknown" said rather than left
 * blank — a token that lapsed used to make the sweep fail every hour with nothing on any screen.
 */
describe('the tracker token, its expiry and its refusal', () => {
    let fixture: ComponentFixture<SettingsTicketing>;
    let http: HttpTestingController;

    const DAY = 86_400_000;

    beforeEach(async () => {
        await TestBed.configureTestingModule({
            imports: [SettingsTicketing],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), SettingsState]
        }).compileComponents();

        TestBed.inject(I18nService).translations.set({
            settings: {
                token_refused_tag: 'Stopped working',
                token_refused: 'Refused (HTTP {{status}}) since {{date}}',
                token_expiry_unknown: 'Expiry unknown',
                token_expires_on: 'Expires on {{date}}',
                token_expiry_declared: '(declared)'
            },
            forges: {
                connections: {
                    expired: 'Expired',
                    expires_soon_one: 'In {{count}} day',
                    expires_soon_other: 'In {{count}} days'
                }
            }
        });

        fixture = TestBed.createComponent(SettingsTicketing);
        fixture.componentRef.setInput('active', true);
        http = TestBed.inject(HttpTestingController);
    });

    async function loaded(state: Record<string, unknown>): Promise<HTMLElement> {
        http.expectOne('/api/v1/settings/ticket-token').flush(asSchema('TicketTokenState', state));
        http.match('/api/v1/settings/webhook-secret').forEach((r) => r.flush({ configured: false }));
        http.match('/api/v1/settings/ticket-webhook-secret').forEach((r) => r.flush({ configured: false }));
        fixture.detectChanges();
        await fixture.whenStable();
        fixture.detectChanges();
        return fixture.nativeElement as HTMLElement;
    }

    const health = (page: HTMLElement): string =>
        page.querySelector('[data-testid="ticket-token-health"]')?.textContent ?? '';

    it('says the tracker refuses the token, with the status and since when, before any date', async () => {
        const page = await loaded({
            configured: true,
            expiresAt: new Date(Date.now() + 5 * DAY).toISOString(),
            expirySource: 'reported',
            refusedStatus: 401,
            refusedSince: '2026-10-12T08:00:00Z'
        });

        expect(health(page)).toContain('Stopped working');
        expect(health(page)).toContain('HTTP 401');
        expect(health(page)).toContain('since 12/10/2026 08:00');
        expect(health(page)).not.toContain('In 5 days');
    });

    it('announces an expiry within fourteen days, in the forge connections words', async () => {
        const page = await loaded({
            configured: true,
            expiresAt: new Date(Date.now() + 10 * DAY - 60_000).toISOString(),
            expirySource: 'reported'
        });

        expect(health(page)).toContain('In 10 days');
    });

    it('says an expired token expired', async () => {
        const page = await loaded({
            configured: true,
            expiresAt: new Date(Date.now() - DAY).toISOString(),
            expirySource: 'declared'
        });

        expect(health(page)).toContain('Expired');
        expect(health(page)).toContain('(declared)');
    });

    // The date the tracker reported was printed year first — "Expire dans 11 jours 2026-09-29" — the one
    // date on the card a French reader had to decode. Written as every other date of the interface, the
    // same in both languages, by UTC day as the server stores it. The shipped bundles, not stand-ins, so
    // the sentence is the one the screen shows.
    const IN_ELEVEN_DAYS = new Date(Date.now() + 11 * DAY - 60_000);
    const day = (at: Date): string =>
        `${String(at.getUTCDate()).padStart(2, '0')}/${String(at.getUTCMonth() + 1).padStart(2, '0')}/${at.getUTCFullYear()}`;
    for (const [lang, bundle, far, soon, past] of [
        ['en', english, 'Expires on 29/09/2027', 'Expires in 11 days', 'Expired'],
        ['fr', french, 'Expire le 29/09/2027', 'Expire dans 11 jours', 'Expiré']
    ] as const) {
        describe(`in ${lang}`, () => {
            beforeEach(() => {
                const i18n = TestBed.inject(I18nService);
                i18n.currentLang.set(lang);
                i18n.translations.set(bundle);
            });

            it('writes a far expiry dd/MM/yyyy', async () => {
                const page = await loaded({
                    configured: true,
                    expiresAt: '2027-09-29T00:00:00Z',
                    expirySource: 'reported'
                });

                expect(health(page)).toContain(far);
                expect(health(page)).not.toContain('2027-09-29');
            });

            it('writes a near expiry dd/MM/yyyy beside its countdown', async () => {
                const page = await loaded({
                    configured: true,
                    expiresAt: IN_ELEVEN_DAYS.toISOString(),
                    expirySource: 'reported'
                });

                expect(health(page)).toContain(soon);
                expect(health(page)).toContain(day(IN_ELEVEN_DAYS));
            });

            it('writes a past expiry dd/MM/yyyy', async () => {
                const page = await loaded({
                    configured: true,
                    expiresAt: '2026-01-05T00:00:00Z',
                    expirySource: 'declared'
                });

                expect(health(page)).toContain(past);
                expect(health(page)).toContain('05/01/2026');
                expect(health(page)).not.toContain('2026-01-05');
            });
        });
    }

    it('says the expiry is unknown rather than nothing', async () => {
        const page = await loaded({ configured: true, expiresAt: null, expirySource: 'unknown' });

        expect(page.querySelector('[data-testid="ticket-token-expiry-unknown"]')).not.toBeNull();
    });

    it('says nothing of a token that is not stored', async () => {
        const page = await loaded({ configured: false, expirySource: 'unknown' });

        expect(page.querySelector('[data-testid="ticket-token-health"]')).toBeNull();
    });
});
