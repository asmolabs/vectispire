import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { beforeEach, describe, expect, it } from 'vitest';
import { asSchema } from '@/app/core/testing/contract';
import { I18nService } from '@/app/core/i18n/i18n.service';
import { SettingsState } from './settings-state';
import { SettingsSiem } from './settings-siem';

/**
 * The SIEM card's collector CA: shown for syslog over TLS only, sent with the requests that read it,
 * and never sent with a protocol that would have the server refuse it.
 */
describe('the SIEM card, its collector CA', () => {
    let fixture: ComponentFixture<SettingsSiem>;
    let http: HttpTestingController;

    const pem = '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----';

    const tls = {
        enabled: true,
        protocol: 'SYSLOG_TLS',
        endpoint: 'collector.corp:6514',
        hasAuthHeader: false,
        minSeverity: 'HIGH',
        tlsCaPem: pem,
        tlsCaSubject: 'CN=Corp SOC Root',
        tlsCaNotAfter: '2027-09-30T12:00:00Z',
        updatedAt: '2026-10-01T06:00:00Z'
    };

    beforeEach(async () => {
        await TestBed.configureTestingModule({
            imports: [SettingsSiem],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), SettingsState]
        }).compileComponents();

        TestBed.inject(I18nService).translations.set({
            settings: {
                siem_ca: 'Collector CA (PEM)',
                siem_ca_pinned: 'Pinned: {{subject}}, valid until {{date}}'
            }
        });

        fixture = TestBed.createComponent(SettingsSiem);
        fixture.componentRef.setInput('active', true);
        http = TestBed.inject(HttpTestingController);
    });

    async function loaded(config: Record<string, unknown>): Promise<HTMLElement> {
        http.expectOne('/api/v1/siem/config').flush(asSchema('SiemConfigResponse', config));
        fixture.detectChanges();
        await fixture.whenStable();
        fixture.detectChanges();
        return fixture.nativeElement as HTMLElement;
    }

    it('shows the pinned CA for syslog over TLS: its PEM, its subject and its expiry', async () => {
        const page = await loaded(tls);

        expect((page.querySelector('#siem-ca') as HTMLTextAreaElement).value).toBe(pem);
        const pinned = page.querySelector('[data-testid="siem-ca-pinned"]')?.textContent ?? '';
        expect(pinned).toContain('CN=Corp SOC Root');
        expect(pinned).toContain('30/09/2027');
    });

    it('has no CA field for the webhook, which verifies no certificate against it', async () => {
        const page = await loaded({
            ...tls,
            protocol: 'WEBHOOK',
            endpoint: 'https://c.corp/cef',
            tlsCaPem: null,
            tlsCaSubject: null,
            tlsCaNotAfter: null
        });

        expect(page.querySelector('#siem-ca')).toBeNull();
    });

    it('saves the CA on screen for TLS — blank removes it — and sends none for another protocol', async () => {
        await loaded(tls);
        const card = fixture.componentInstance;

        card.siemForm.tlsCaPem = `  ${pem}\n`;
        card.saveSiemConfig();
        const kept = http.expectOne('/api/v1/siem/config');
        expect(kept.request.body.tlsCaPem).toBe(pem);
        kept.flush(asSchema('SiemConfigResponse', tls));

        card.siemForm.tlsCaPem = '';
        card.saveSiemConfig();
        const removed = http.expectOne('/api/v1/siem/config');
        expect(removed.request.body.tlsCaPem).toBe('');
        removed.flush(
            asSchema('SiemConfigResponse', { ...tls, tlsCaPem: null, tlsCaSubject: null, tlsCaNotAfter: null })
        );

        card.siemForm.protocol = 'SYSLOG_TCP';
        card.siemForm.tlsCaPem = pem;
        card.saveSiemConfig();
        // Undefined, which the JSON body leaves out: absent, not blank, so nothing is removed by it.
        expect(http.expectOne('/api/v1/siem/config').request.body.tlsCaPem).toBeUndefined();
    });

    it('tests the CA on screen, saved or not', async () => {
        await loaded(tls);
        const card = fixture.componentInstance;

        card.siemForm.tlsCaPem = 'unsaved';
        card.testSiem();

        expect(http.expectOne('/api/v1/siem/test').request.body.tlsCaPem).toBe('unsaved');
    });
});
