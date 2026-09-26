import { HttpClient, provideHttpClient, withInterceptors, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { Router, UrlTree, provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { authInterceptor } from './auth.interceptor';
import { SessionStore } from './session.store';

/** The 401 that ends a session, and the page it should not make the person lose. */
describe('the session interceptor', () => {
    let http: HttpTestingController;
    let router: Router;
    let session: SessionStore;
    let navigate: ReturnType<typeof vi.spyOn>;

    beforeEach(() => {
        TestBed.resetTestingModule();
        TestBed.configureTestingModule({
            providers: [
                provideHttpClient(withXhr(), withInterceptors([authInterceptor])),
                provideHttpClientTesting(),
                provideRouter([])
            ]
        });
        http = TestBed.inject(HttpTestingController);
        router = TestBed.inject(Router);
        session = TestBed.inject(SessionStore);
        navigate = vi.spyOn(router, 'navigateByUrl').mockResolvedValue(true);
        session.open('expired', { username: 'x', role: 'USER', mustChangePassword: false } as never);
    });

    function where(): string {
        const [target] = navigate.mock.lastCall as [UrlTree];
        return router.serializeUrl(target);
    }

    it('signs out on a 401 and remembers the page, so signing in again returns to it', () => {
        vi.spyOn(router, 'url', 'get').mockReturnValue('/issues?overdue=true');
        TestBed.inject(HttpClient)
            .get('/api/v1/issues')
            .subscribe({ error: () => undefined });
        http.expectOne('/api/v1/issues').flush({}, { status: 401, statusText: 'Unauthorized' });

        expect(session.isAuthenticated()).toBe(false);
        expect(where()).toBe('/login?returnUrl=%2Fissues%3Foverdue%3Dtrue');
        expect(navigate.mock.lastCall?.[1]).toEqual({ replaceUrl: true });
    });

    it('does not ask the sign-in page to return to itself', () => {
        vi.spyOn(router, 'url', 'get').mockReturnValue('/login');
        TestBed.inject(HttpClient)
            .get('/api/v1/auth/me')
            .subscribe({ error: () => undefined });
        http.expectOne('/api/v1/auth/me').flush({}, { status: 401, statusText: 'Unauthorized' });

        expect(where()).toBe('/login');
    });
});
