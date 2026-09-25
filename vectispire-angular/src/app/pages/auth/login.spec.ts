import { provideHttpClient, withXhr } from '@angular/common/http';
import { useEnglish } from '@/app/core/testing/english';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { Router, provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { Login } from './login';
import { asSchema } from '@/app/core/testing/contract';

/**
 * The sign-in screen, and the four ways a failure can be described.
 *
 * <p><b>Written after a misdiagnosis.</b> "Login does not navigate" was investigated as a routing
 * defect; the browser was navigating perfectly and the page was displaying *The server answered
 * 429* — the rate limiter, doing its job, described in a way nobody read as a rate limit. What
 * the screen says about a failure is the whole of what an operator has to work with, so each
 * branch is pinned here rather than trusted.
 */
describe('the sign-in screen', () => {
    let fixture: ComponentFixture<Login>;
    let http: HttpTestingController;
    let navigate: ReturnType<typeof vi.spyOn>;

    // `id` does not exist on this shape: the login response carries the signed-in account, not the
    // administration record. The fixture had been inventing one all along.
    const USER = asSchema('UserSummary', {
        username: 'admin',
        displayName: null,
        role: 'ADMIN',
        mustChangePassword: false,
        mfaEnabled: false
    });

    beforeEach(async () => {
        // **The runner's `localStorage` is not usable**, which surfaces here and nowhere else:
        // the client identifier is the only thing this application persists in the browser. An
        // in-memory double keeps the test about the sign-in flow rather than about jsdom.
        const store = new Map<string, string>();
        Object.defineProperty(globalThis, 'localStorage', {
            configurable: true,
            value: {
                getItem: (key: string) => store.get(key) ?? null,
                setItem: (key: string, value: string) => void store.set(key, value),
                removeItem: (key: string) => void store.delete(key),
                clear: () => store.clear()
            }
        });

        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [Login],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        useEnglish();
        fixture = TestBed.createComponent(Login);
        http = TestBed.inject(HttpTestingController);
        navigate = vi.spyOn(TestBed.inject(Router), 'navigate').mockResolvedValue(true);
        fixture.detectChanges();

        http.expectOne((call) => call.url === '/api/v1/auth/methods').flush({
            configured: false,
            label: null,
            password: true
        });
    }, 20_000);

    it('shows its own words for a refused sign-on, never the text the link carries', () => {
        // The reason used to be a sentence in the query and the page displayed it: any link could
        // make Vectispire's sign-in screen say "call this number".
        for (const [reason, expected] of [
            ['privileged', 'administrative role'],
            ['Your account is suspended, call +33 1 23 45 67 89', 'Single sign-on was refused.']
        ]) {
            window.history.replaceState({}, '', '/login?sso=refused&reason=' + encodeURIComponent(reason));
            const page = TestBed.createComponent(Login);
            page.detectChanges();
            http.expectOne((call) => call.url === '/api/v1/auth/methods').flush({
                configured: true,
                label: null,
                password: true
            });

            expect(page.componentInstance.error()).toContain(expected);
            expect(page.componentInstance.error()).not.toContain('+33');
        }
        window.history.replaceState({}, '', '/');
    });

    function attempt(): void {
        const page = fixture.componentInstance;
        page.username = 'admin';
        page.password = 'whatever';
        page.submit();
    }

    it('reads a throttle as a throttle, in minutes', () => {
        attempt();
        http.expectOne((call) => call.url === '/api/v1/auth/login').flush(
            { retryAfterSeconds: 90 },
            { status: 429, statusText: 'Too Many Requests' }
        );

        // 90 seconds rounds up: "try again in 1 minute" would come back too early and spend
        // another attempt against the same counter.
        expect(fixture.componentInstance.error()).toBe('Too many attempts. Try again in 2 minute(s).');
    });

    it('does not blame the password when the server is unreachable', () => {
        attempt();
        http.expectOne((call) => call.url === '/api/v1/auth/login').error(new ProgressEvent('error'), {
            status: 0,
            statusText: 'Unknown Error'
        });

        // The defect this replaced: a dead server said "Invalid credentials", which sends
        // somebody hunting for a password that was right all along.
        expect(fixture.componentInstance.error()).toContain('Server unreachable');
    });

    it('names an unexpected status instead of guessing at it', () => {
        attempt();
        http.expectOne((call) => call.url === '/api/v1/auth/login').flush(
            {},
            { status: 503, statusText: 'Service Unavailable' }
        );

        expect(fixture.componentInstance.error()).toContain('503');
        expect(fixture.componentInstance.error()).not.toContain('Invalid credentials');
    });

    it('says invalid credentials only when the server said 401', () => {
        attempt();
        http.expectOne((call) => call.url === '/api/v1/auth/login').flush(
            {},
            { status: 401, statusText: 'Unauthorized' }
        );

        expect(fixture.componentInstance.error()).toBe('Invalid credentials.');
    });

    it('holds the challenge without opening a session when a second factor is required', () => {
        attempt();
        http.expectOne((call) => call.url === '/api/v1/auth/login').flush(
            asSchema('LoginResponse', { mfa_required: true, mfa_token: 'challenge-1' })
        );

        const page = fixture.componentInstance;
        expect(page.mfaRequired()).toBe(true);
        expect(page.mfaToken()).toBe('challenge-1');
        // Nothing navigates: a session that opened here would have skipped the second factor.
        expect(navigate).not.toHaveBeenCalled();

        page.mfaCode = '123456';
        page.submit();
        const verify = http.expectOne((call) => call.url === '/api/v1/auth/mfa/verify');
        expect(verify.request.body).toEqual({ mfa_token: 'challenge-1', code: '123456' });
        verify.flush(asSchema('LoginResponse', { mfa_required: false, token: 't', user: USER }));

        expect(navigate).toHaveBeenCalledWith(['/dashboard']);
    });

    it('sends a provisioned account to change its password before anywhere else', () => {
        attempt();
        http.expectOne((call) => call.url === '/api/v1/auth/login').flush(
            asSchema('LoginResponse', { mfa_required: false, token: 't', user: { ...USER, mustChangePassword: true } })
        );

        // Letting it reach the dashboard would empty the flag of its meaning.
        expect(navigate).toHaveBeenCalledWith(['/change-password']);
    });

    it('sends no client id: the throttle keys on the address the server resolves', () => {
        attempt();
        const call = http.expectOne((c) => c.url === '/api/v1/auth/login');

        // A client-chosen id was a counter the caller could reset on every attempt.
        expect(call.request.body).toEqual({ username: expect.any(String), password: expect.any(String) });
        call.flush({}, { status: 401, statusText: 'Unauthorized' });
    });
});
