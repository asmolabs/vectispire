import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { Router, provideRouter } from '@angular/router';
import { RouterTestingHarness } from '@angular/router/testing';
import { beforeEach, describe, expect, it } from 'vitest';
import { appRoutes } from '../../app.routes';
import { safeReturnUrl } from './auth.guard';
import { SessionStore } from './session.store';
import { useEnglish } from './testing/english';

/**
 * The shell's guard, exercised through **the application's own route table.**
 *
 * <p>A guard function can pass every test of its own and guard nothing, if the route that should
 * carry it does not — which is how the shell came to mount for anybody: `requires(…)` was tested
 * and sat on fifteen routes, and the parent of all of them had none. So these cases navigate
 * `appRoutes` as the browser would, and look at where the router ends up and what was requested.
 */
describe('the shell, signed out', () => {
    let router: Router;
    let session: SessionStore;
    let http: HttpTestingController;

    beforeEach(() => {
        TestBed.resetTestingModule();
        TestBed.configureTestingModule({
            providers: [provideRouter(appRoutes), provideHttpClient(withXhr()), provideHttpClientTesting()]
        });
        useEnglish();
        router = TestBed.inject(Router);
        session = TestBed.inject(SessionStore);
        http = TestBed.inject(HttpTestingController);
        session.close();
    });

    it('sends a reload to sign in, remembering the page and its filter, and calls nothing else', async () => {
        const harness = await RouterTestingHarness.create();
        await harness.navigateByUrl('/issues?is_kev=true');

        expect(router.url).toBe('/login?returnUrl=%2Fissues%3Fis_kev%3Dtrue');
        // The sign-in page asks which ways in exist; nothing of the shell's screen was requested.
        const calls = http.match(() => true).map((call) => call.request.url);
        expect(calls.every((url) => url === '/api/v1/auth/methods')).toBe(true);
    });

    it('does not bother remembering the root', async () => {
        const harness = await RouterTestingHarness.create();
        await harness.navigateByUrl('/');

        expect(router.url).toBe('/login');
    });

    it('keeps a provisioned account on the password change, wherever it tries to go', async () => {
        session.open('token', { username: 'x', role: 'ADMIN', mustChangePassword: true } as never);
        const harness = await RouterTestingHarness.create();
        await harness.navigateByUrl('/forbidden');

        expect(router.url).toBe('/change-password');
    });

    it('lets a session in', async () => {
        session.open('token', { username: 'x', role: 'USER', mustChangePassword: false } as never);
        const harness = await RouterTestingHarness.create();
        await harness.navigateByUrl('/forbidden');

        expect(router.url).toBe('/forbidden');
    });
});

describe('the address to return to after signing in', () => {
    it("accepts this application's paths, query included", () => {
        expect(safeReturnUrl('/issues')).toBe('/issues');
        expect(safeReturnUrl('/issues?is_kev=true&overdue=true')).toBe('/issues?is_kev=true&overdue=true');
        expect(safeReturnUrl('/scans/12')).toBe('/scans/12');
    });

    it('refuses anything a browser would take off this origin', () => {
        for (const value of [
            '//evil.example',
            '//evil.example/issues',
            '/\\evil.example',
            '/\t/evil.example',
            'https://evil.example',
            'javascript:alert(1)',
            'issues'
        ]) {
            expect(safeReturnUrl(value), value).toBeNull();
        }
    });

    it('refuses what has nothing to remember or would loop', () => {
        for (const value of [null, '', '/', '/login', '/login?returnUrl=%2Fissues']) {
            expect(safeReturnUrl(value), String(value)).toBeNull();
        }
    });
});
