import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { Router, provideRouter, withComponentInputBinding } from '@angular/router';
import { RouterTestingHarness } from '@angular/router/testing';
import { beforeEach, describe, expect, it } from 'vitest';
import { appRoutes } from '../../../app.routes';
import { SessionStore } from '../../core/session.store';
import { useEnglish } from '../../core/testing/english';

/**
 * The password change, through the application's own route table and with the input binding the
 * application uses: the `returnUrl` reaches the screen only if both are as in production.
 *
 * <p><b>It used to end on the dashboard, always.</b> A provisioned account following a link it had
 * been handed signed in, was sent to change its password, and lost the link on the way; the same
 * happened to anybody changing their password from the topbar. The page asked for now survives the
 * change — and only a page of this application does, since the parameter is anybody's to write.
 */
describe('the password change', () => {
    let router: Router;
    let session: SessionStore;
    let http: HttpTestingController;
    let harness: RouterTestingHarness;

    beforeEach(async () => {
        TestBed.resetTestingModule();
        TestBed.configureTestingModule({
            providers: [
                provideRouter(appRoutes, withComponentInputBinding()),
                provideHttpClient(withXhr()),
                provideHttpClientTesting()
            ]
        });
        useEnglish();
        router = TestBed.inject(Router);
        session = TestBed.inject(SessionStore);
        http = TestBed.inject(HttpTestingController);
        harness = await RouterTestingHarness.create();
    });

    function type(id: string, value: string): void {
        const field = document.querySelector<HTMLInputElement>(`#${id} input`)!;
        field.value = value;
        field.dispatchEvent(new Event('input'));
        harness.detectChanges();
    }

    async function change(): Promise<void> {
        type('current', 'provisioned-password');
        type('next', 'a-long-new-password');
        type('confirm', 'a-long-new-password');
        document.querySelector<HTMLButtonElement>('button[type="submit"]')!.click();
        harness.detectChanges();

        const request = http.expectOne('/api/v1/auth/change-password');
        expect(request.request.body).toEqual({
            current_password: 'provisioned-password',
            new_password: 'a-long-new-password'
        });
        request.flush({ mustChangePassword: false });
        await harness.fixture.whenStable();
    }

    it('takes a provisioned account to the page it asked for once the password is changed', async () => {
        session.open('token', { username: 'x', role: 'USER', mustChangePassword: true } as never);
        await harness.navigateByUrl('/forbidden?from=link');
        expect(router.url).toBe('/change-password?returnUrl=%2Fforbidden%3Ffrom%3Dlink');

        await change();

        expect(router.url).toBe('/forbidden?from=link');
        expect(session.mustChangePassword()).toBe(false);
    });

    it('goes to the dashboard when nothing was asked for', async () => {
        session.open('token', { username: 'x', role: 'USER', mustChangePassword: false } as never);
        await harness.navigateByUrl('/change-password');

        await change();

        expect(router.url).toBe('/dashboard');
    });

    it('never follows a returnUrl off this application', async () => {
        session.open('token', { username: 'x', role: 'USER', mustChangePassword: false } as never);
        for (const hostile of ['//evil.example', 'https://evil.example/', '/\\evil.example', 'javascript:alert(1)']) {
            await harness.navigateByUrl(`/change-password?returnUrl=${encodeURIComponent(hostile)}`);

            await change();

            expect(router.url, hostile).toBe('/dashboard');
        }
    });

    it('refuses a confirmation that differs, without asking the server', async () => {
        session.open('token', { username: 'x', role: 'USER', mustChangePassword: false } as never);
        await harness.navigateByUrl('/change-password');

        type('current', 'provisioned-password');
        type('next', 'a-long-new-password');
        type('confirm', 'a-long-new-passwort');
        document.querySelector<HTMLButtonElement>('button[type="submit"]')!.click();
        harness.detectChanges();

        http.expectNone('/api/v1/auth/change-password');
        expect(document.querySelector('p-message')?.textContent).toContain(
            'The new password and its confirmation differ.'
        );
    });

    it("shows the server's reason for refusing the new password, and stays", async () => {
        session.open('token', { username: 'x', role: 'USER', mustChangePassword: false } as never);
        await harness.navigateByUrl('/change-password?returnUrl=%2Fforbidden');

        type('current', 'provisioned-password');
        type('next', 'short');
        type('confirm', 'short');
        document.querySelector<HTMLButtonElement>('button[type="submit"]')!.click();
        harness.detectChanges();
        http.expectOne('/api/v1/auth/change-password').flush(
            { detail: 'A password has at least 12 characters.' },
            { status: 400, statusText: 'Bad Request' }
        );
        harness.detectChanges();

        expect(router.url).toBe('/change-password?returnUrl=%2Fforbidden');
        expect(document.querySelector('p-message')?.textContent).toContain('A password has at least 12 characters.');
    });
});
