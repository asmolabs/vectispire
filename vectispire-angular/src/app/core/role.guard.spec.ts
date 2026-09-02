import { TestBed } from '@angular/core/testing';
import { provideRouter, Router, UrlTree } from '@angular/router';
import { describe, expect, it, beforeEach } from 'vitest';
import { requires, Need } from './role.guard';
import { SessionStore } from './session.store';

/**
 * The guards, and the two ways they can be wrong.
 *
 * <p>A guard that refuses everybody is caught the first time anyone signs in. A guard that lets
 * everybody through is invisible: the server still refuses, the screen still shows "Could not
 * load…", and the fix is silently gone. Every case here therefore asserts both directions.
 */
describe('the role guards', () => {
    let session: SessionStore;
    let router: Router;

    beforeEach(() => {
        TestBed.configureTestingModule({ providers: [provideRouter([])] });
        session = TestBed.inject(SessionStore);
        router = TestBed.inject(Router);
    });

    function attempt(need: Need, role: string | null): true | UrlTree {
        if (role === null) {
            session.close();
        } else {
            session.open('token', { id: 1, username: 'x', role, mustChangePassword: false } as never);
        }
        const guard = requires(need);
        return TestBed.runInInjectionContext(
            () => guard({ routeConfig: { path: 'settings' } } as never, {} as never)
        ) as true | UrlTree;
    }

    function refusedTo(result: true | UrlTree): string {
        return result === true ? 'ALLOWED' : router.serializeUrl(result).split('?')[0];
    }

    it('sends an account with no session to sign in, not to a refusal', () => {
        // **Signed out is not the same as not allowed.** Telling somebody they lack a role when
        // they lack a session sends them looking for an administrator instead of a login form.
        expect(refusedTo(attempt('administrator', null))).toBe('/login');
    });

    it('opens administrator pages to administrators and to nobody else', () => {
        expect(attempt('administrator', 'ADMIN')).toBe(true);
        expect(attempt('administrator', 'SUPERUSER')).toBe(true);
        expect(refusedTo(attempt('administrator', 'CISO'))).toBe('/forbidden');
        expect(refusedTo(attempt('administrator', 'AUDITOR'))).toBe('/forbidden');
        expect(refusedTo(attempt('administrator', 'USER'))).toBe('/forbidden');
    });

    it('opens governance writing to the CISO, and refuses the auditor', () => {
        expect(attempt('security-lead', 'CISO')).toBe(true);
        expect(attempt('security-lead', 'ADMIN')).toBe(true);
        expect(refusedTo(attempt('security-lead', 'AUDITOR'))).toBe('/forbidden');
        expect(refusedTo(attempt('security-lead', 'USER'))).toBe('/forbidden');
    });

    it('opens governance reading to the auditor — the reason the role exists', () => {
        expect(attempt('governance-read', 'AUDITOR')).toBe(true);
        expect(attempt('governance-read', 'CISO')).toBe(true);
        expect(attempt('governance-read', 'ADMIN')).toBe(true);
        // Widening the read must not have widened it to everybody.
        expect(refusedTo(attempt('governance-read', 'USER'))).toBe('/forbidden');
        expect(refusedTo(attempt('governance-read', 'SECURITY_CHAMPION'))).toBe('/forbidden');
    });

    it('names the page it refused, so the refusal is not a dead end', () => {
        const result = attempt('administrator', 'USER') as UrlTree;
        const url = router.serializeUrl(result);
        expect(url).toContain('need=administrator');
        expect(url).toContain('page=settings');
    });
});
