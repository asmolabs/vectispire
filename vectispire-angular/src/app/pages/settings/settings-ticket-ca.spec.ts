import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { beforeEach, describe, expect, it } from 'vitest';
import { asSchema } from '@/app/core/testing/contract';
import { I18nService } from '@/app/core/i18n/i18n.service';
import type { SettingDefinition } from '@/app/core/api.models';
import { SessionStore } from '@/app/core/session.store';
import { SettingsCatalog } from './settings-catalog';
import { SettingsState } from './settings-state';
import { sessionUser } from '@/app/core/testing/session.fixtures';

/**
 * The tracker CA in the tracker card: a PEM bundle is several lines, so it is a text area and not the
 * one-line input every other text setting gets — which would join the lines and have the server refuse
 * the paste — and what is pinned is shown by its subject and expiry, as the forge connections show theirs.
 */
describe('the tracker CA field', () => {
    let fixture: ComponentFixture<SettingsCatalog>;
    let http: HttpTestingController;

    const pem = '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----';

    const CATALOGUE = asSchema('Catalog', {
        settings: [
            {
                key: 'ticket_base_url',
                section: 'Ticket tracker',
                label: 'Tracker URL',
                help: 'Where the tracker is.',
                type: 'text',
                value: 'https://gitlab.corp',
                default: '',
                configured: true,
                governor_only: false,
                administrator_only: true
            },
            {
                key: 'ticket_ca_pem',
                section: 'Ticket tracker',
                label: 'Tracker CA (PEM)',
                help: 'The CA the tracker chains to.',
                type: 'text',
                value: pem,
                default: '',
                configured: true,
                governor_only: false,
                administrator_only: true
            }
        ]
    });

    async function render(role: string): Promise<HTMLElement> {
        await TestBed.configureTestingModule({
            imports: [SettingsCatalog],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), SettingsState]
        }).compileComponents();

        TestBed.inject(I18nService).translations.set({
            settings: { ticket_ca_pinned: 'Pinned: {{subject}}, valid until {{date}}' }
        });
        TestBed.inject(SessionStore).open('a-token', sessionUser(role, { username: 'someone' }));
        http = TestBed.inject(HttpTestingController);

        fixture = TestBed.createComponent(SettingsCatalog);
        fixture.componentRef.setInput('tab', 'integrations');
        fixture.detectChanges();

        const state = TestBed.inject(SettingsState);
        state.catalog.set(CATALOGUE.settings as SettingDefinition[]);
        state.values.set(Object.fromEntries(CATALOGUE.settings.map((s) => [s.key, s.value ?? ''])));
        fixture.detectChanges();
        await fixture.whenStable();
        fixture.detectChanges();
        return fixture.nativeElement as HTMLElement;
    }

    beforeEach(() => TestBed.resetTestingModule());

    it('is a text area holding the bundle, with the subject and expiry of what is pinned', async () => {
        const page = await render('ADMIN');
        http.expectOne('/api/v1/settings/ticket-ca').flush(
            asSchema('TicketCaState', { pinned: true, subject: 'CN=Corp Root', notAfter: '2027-09-30T12:00:00Z' })
        );
        fixture.detectChanges();

        const area = page.querySelector('textarea#ticket_ca_pem') as HTMLTextAreaElement;
        expect(area).not.toBeNull();
        await fixture.whenStable();
        expect(area.value).toBe(pem);
        expect(area.disabled).toBe(false);
        const pinned = page.querySelector('[data-testid="ticket-ca-pinned"]')?.textContent ?? '';
        expect(pinned).toContain('CN=Corp Root');
        expect(pinned).toContain('30/09/2027');
    });

    it('keeps every line of a paste, for the save to send', async () => {
        const page = await render('ADMIN');
        http.expectOne('/api/v1/settings/ticket-ca').flush(
            asSchema('TicketCaState', { pinned: false, subject: null, notAfter: null })
        );

        const area = page.querySelector('textarea#ticket_ca_pem') as HTMLTextAreaElement;
        const bundle = `${pem}\n${pem}`;
        area.value = bundle;
        area.dispatchEvent(new Event('input'));
        expect(TestBed.inject(SettingsState).values()['ticket_ca_pem']).toBe(bundle);
    });

    it('says when the stored text no longer reads as a CA, rather than nothing', async () => {
        const page = await render('ADMIN');
        http.expectOne('/api/v1/settings/ticket-ca').flush(
            asSchema('TicketCaState', { pinned: true, subject: null, notAfter: null })
        );
        fixture.detectChanges();

        expect(page.querySelector('[data-testid="ticket-ca-unreadable"]')).not.toBeNull();
        expect(page.querySelector('[data-testid="ticket-ca-pinned"]')).toBeNull();
    });

    it('is greyed out for a CISO, and its state is not asked for', async () => {
        const page = await render('CISO');
        http.expectNone('/api/v1/settings/ticket-ca');

        expect((page.querySelector('textarea#ticket_ca_pem') as HTMLTextAreaElement).disabled).toBe(true);
    });
});
