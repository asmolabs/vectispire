import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { Account } from './account';
import { SessionStore } from '@/app/core/session.store';
import { I18nService } from '@/app/core/i18n/i18n.service';
import { asSchema } from '@/app/core/testing/contract';

/**
 * L'enrôlement du second facteur.
 *
 * <p><b>Ces cas existent parce que le facteur était complet et inactivable.</b> Le service TOTP,
 * la table des défis, les quatre routes et la page de connexion qui sait répondre à un défi :
 * tout était livré, et aucun écran n'appelait quoi que ce soit. Rien ne pouvait le voir — le
 * produit n'était pas cassé, il était muet.
 *
 * <p>Ce qui est éprouvé ici est la forme en deux temps, qui est ce qui rend l'enrôlement sûr :
 * <b>rien n'est activé tant qu'un premier code n'a pas été vérifié</b>, et un refus garde
 * l'enrôlement ouvert au lieu de redistribuer un secret pour une faute de frappe.
 */
describe("l'écran du compte", () => {
    let fixture: ComponentFixture<Account>;
    let http: HttpTestingController;
    let session: SessionStore;

    beforeEach(async () => {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [Account],
            providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])]
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

    it("n'active rien tant que le premier code n'est pas vérifié", () => {
        const page = fixture.componentInstance;
        page.begin();
        http.expectOne((call) => call.url === '/api/v1/auth/mfa/setup').flush(SETUP);
        fixture.detectChanges();

        // **Le secret proposé n'est pas un facteur activé.** Une horloge décalée ou un secret mal
        // recopié ne se verrait sinon qu'à la déconnexion suivante, c'est-à-dire trop tard.
        expect(page.mfaEnabled()).toBe(false);
        expect(fixture.nativeElement.textContent).toContain('JBSW Y3DP EHPK 3PXP');

        page.code = '123456';
        page.confirm();
        const enable = http.expectOne((call) => call.url === '/api/v1/auth/mfa/enable');
        expect(enable.request.body).toEqual({ secret: SETUP.secret, code: '123456' });
        enable.flush({ success: true, backupCodes: ['aaaa-1111', 'bbbb-2222'] });
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
            .flush({ success: true, backupCodes: ['aaaa-1111', 'bbbb-2222'] });
        fixture.detectChanges();

        // Le serveur les chiffre et ne les rendra plus : sans l'avertissement, on ferme l'onglet
        // en pensant les retrouver.
        const text = fixture.nativeElement.textContent as string;
        expect(text).toContain('Write these down now');
        expect(text).toContain('aaaa-1111');
        expect(text).toContain('bbbb-2222');
    });

    it("garde l'enrôlement ouvert quand le code est refusé", () => {
        const page = fixture.componentInstance;
        page.begin();
        http.expectOne((call) => call.url === '/api/v1/auth/mfa/setup').flush(SETUP);

        page.code = '000000';
        page.confirm();
        http.expectOne((call) => call.url === '/api/v1/auth/mfa/enable')
            .flush({ message: 'Invalid TOTP verification code.' }, { status: 400, statusText: 'Bad Request' });
        fixture.detectChanges();

        // Six chiffres et trente secondes de vie : se tromper est ordinaire. Redistribuer un
        // secret neuf pour une faute de frappe obligerait à tout recopier.
        expect(page.enrolment()).not.toBeNull();
        expect(page.mfaEnabled()).toBe(false);
        expect(page.error()).toContain('Invalid TOTP verification code.');
    });

    it('exige un code pour retirer le facteur, et le garde actif si le serveur refuse', () => {
        session.setMfaEnabled(true);
        fixture.detectChanges();

        const page = fixture.componentInstance;
        page.askRemoval();

        // Sans code, rien ne part : c'est le serveur qui l'exige, et un écran qui enverrait une
        // demande vide ferait d'un poste déverrouillé une minute un désarmement.
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

    it('retire le facteur quand le code est accepté', () => {
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
