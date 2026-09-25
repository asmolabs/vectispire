import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { Account } from './account';
import { SessionStore } from '@/app/core/session.store';
import { I18nService } from '@/app/core/i18n/i18n.service';
import { asSchema } from '@/app/core/testing/contract';

/**
 * Enrolling the second factor.
 *
 * <p><b>These cases exist because the factor was complete and could not be enabled.</b> The TOTP
 * service, the challenge table, the four routes and a sign-in page that knows how to answer a
 * challenge: all of it shipped, and no screen called any of it. Nothing could see it — the product
 * was not broken, it was silent.
 *
 * <p>What is tested here is the two-step shape, which is what makes enrolment safe: <b>nothing is
 * switched on until a first code has been verified</b>, and a refusal keeps enrolment open instead
 * of reissuing a secret over a typo.
 */
describe('the account screen', () => {
    let fixture: ComponentFixture<Account>;
    let http: HttpTestingController;
    let session: SessionStore;

    beforeEach(async () => {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [Account],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        TestBed.inject(I18nService).translations.set({
            common: { cancel: 'Cancel' },
            account: {
                title: 'My account', subtitle: '—', identity: 'Account', change_password: 'Change password',
                mfa: 'Authentication', mfa_totp: 'Second factor', mfa_on: 'On', mfa_off: 'Off',
                mfa_help: '—', mfa_enable: 'Turn on', mfa_scan: '—', mfa_code: 'Code',
                mfa_confirm: 'Verify and turn on', mfa_disable: 'Turn off', mfa_disable_help: '—',
                mfa_setup_failed: 'no secret', mfa_enable_failed: 'That code was not accepted.',
                mfa_disable_failed: 'still on', backup_warning: 'Write these down now'
            }
        });

        session = TestBed.inject(SessionStore);
        session.open('a-token', { username: 'c.moreau', displayName: null, role: 'USER', mustChangePassword: false, mfaEnabled: false });

        http = TestBed.inject(HttpTestingController);
        fixture = TestBed.createComponent(Account);
        fixture.detectChanges();
    }, 20_000);

    const SETUP = asSchema('SetupResponse', {
        secret: 'JBSWY3DPEHPK3PXP',
        qrCodeUri: 'otpauth://totp/Vectispire:c.moreau?secret=JBSWY3DPEHPK3PXP',
        issuer: 'Vectispire'
    });

    it('switches nothing on until the first code is verified', () => {
        const page = fixture.componentInstance;
        page.begin();
        http.expectOne((call) => call.url === '/api/v1/auth/mfa/setup').flush(SETUP);
        fixture.detectChanges();

        // **The secret offered is not a factor switched on.** A clock that is out or a secret
        // copied wrong would otherwise show only at the next sign-out, that is too late.
        expect(page.mfaEnabled()).toBe(false);
        expect(fixture.nativeElement.textContent).toContain('JBSW Y3DP EHPK 3PXP');

        page.code = '123456';
        page.confirm();
        const enable = http.expectOne((call) => call.url === '/api/v1/auth/mfa/enable');
        expect(enable.request.body).toEqual({ secret: SETUP.secret, code: '123456' });
        enable.flush(asSchema('EnableResponse', { success: true, backupCodes: ['aaaa-1111', 'bbbb-2222'] }));
        fixture.detectChanges();

        expect(page.mfaEnabled()).toBe(true);
        expect(page.enrolment()).toBeNull();
    });

    it('montre les codes de secours une fois, en disant que ce sera la seule', () => {
        const page = fixture.componentInstance;
        page.begin();
        http.expectOne((call) => call.url === '/api/v1/auth/mfa/setup').flush(SETUP);
        page.code = '123456';
        page.confirm();
        http.expectOne((call) => call.url === '/api/v1/auth/mfa/enable')
            .flush(asSchema('EnableResponse', { success: true, backupCodes: ['aaaa-1111', 'bbbb-2222'] }));
        fixture.detectChanges();

        // Le serveur les chiffre et ne les rendra plus : sans l'avertissement, on ferme l'onglet
        // en pensant les retrouver.
        const text = fixture.nativeElement.textContent as string;
        expect(text).toContain('Write these down now');
        expect(text).toContain('aaaa-1111');
        expect(text).toContain('bbbb-2222');
    });

    it('keeps enrolment open when the code is refused', () => {
        const page = fixture.componentInstance;
        page.begin();
        http.expectOne((call) => call.url === '/api/v1/auth/mfa/setup').flush(SETUP);

        page.code = '000000';
        page.confirm();
        http.expectOne((call) => call.url === '/api/v1/auth/mfa/enable')
            .flush({ message: 'Invalid TOTP verification code.' }, { status: 400, statusText: 'Bad Request' });
        fixture.detectChanges();

        // Six digits and thirty seconds of life: getting it wrong is ordinary. Reissuing a fresh
        // secret over a typo would mean copying everything again.
        expect(page.enrolment()).not.toBeNull();
        expect(page.mfaEnabled()).toBe(false);
        expect(page.error()).toContain('Invalid TOTP verification code.');
    });

    it('exige un code pour retirer le facteur, et le garde actif si le serveur refuse', () => {
        session.setMfaEnabled(true);
        fixture.detectChanges();

        const page = fixture.componentInstance;
        page.askRemoval();

        // With no code, nothing is sent: the server requires it, and a screen sending an empty
        // request would turn a workstation unlocked for a minute into a disarming.
        page.code = '';
        page.remove();
        http.expectNone((call) => call.url === '/api/v1/auth/mfa/disable');

        page.code = '000000';
        page.remove();
        http.expectOne((call) => call.url === '/api/v1/auth/mfa/disable')
            .flush({ message: 'Invalid code.' }, { status: 400, statusText: 'Bad Request' });

        expect(page.mfaEnabled()).toBe(true);
        expect(page.removing()).toBe(true);
    });

    it('removes the factor when the code is accepted', () => {
        session.setMfaEnabled(true);
        fixture.detectChanges();

        const page = fixture.componentInstance;
        page.askRemoval();
        page.code = '123456';
        page.remove();

        const call = http.expectOne((request) => request.url === '/api/v1/auth/mfa/disable');
        expect(call.request.body).toEqual({ code: '123456' });
        call.flush({ mfaEnabled: false });

        expect(page.mfaEnabled()).toBe(false);
        expect(page.removing()).toBe(false);
    });
});
