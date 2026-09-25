import { TestBed, ComponentFixture } from '@angular/core/testing';
import { describe, beforeEach, it, expect, vi } from 'vitest';
import { provideRouter, Router } from '@angular/router';
import { HttpClient } from '@angular/common/http';
import { of, throwError, Subject } from 'rxjs';
import { AppTopbar } from './app.topbar';
import { AuthApi } from '@/app/core/api/auth.api';
import { SessionStore } from '@/app/core/session.store';
import { I18nService } from '@/app/core/i18n/i18n.service';

/**
 * The sign-out button.
 *
 * <p><b>This case exists because the button never did anything.</b> It carried its icon, its
 * translated label and no handler: you clicked, nothing moved, the token stayed in memory and the
 * session stayed open on the server. No suite could see it — the template did show something, and
 * that was all anybody asked of it.
 *
 * <p>What is tested here is therefore not that a button is displayed, but the three effects it
 * must produce: <b>the server is told</b>, <b>the browser forgets</b> and <b>the screen goes
 * elsewhere</b> — including when the server does not answer, the case where the last two matter
 * most.
 */
describe('la barre du haut', () => {
    let fixture: ComponentFixture<AppTopbar>;
    let session: SessionStore;
    let logout: ReturnType<typeof vi.fn>;
    let router: Router;

    beforeEach(async () => {
        logout = vi.fn().mockReturnValue(of(undefined));

        await TestBed.configureTestingModule({
            imports: [AppTopbar],
            providers: [
                provideRouter([]),
                { provide: HttpClient, useValue: { get: vi.fn().mockReturnValue(of({})) } },
                { provide: AuthApi, useValue: { logout, signInMethods: () => of({}) } }
            ]
        }).compileComponents();

        TestBed.inject(I18nService).translations.set({
            topbar: {
                sign_out: 'Sign out',
                password: 'Password',
                account: 'Account',
                appearance: 'Appearance',
                language: 'Language'
            }
        });

        session = TestBed.inject(SessionStore);
        session.open('a-token', { username: 'c.moreau', role: 'USER' } as never);

        router = TestBed.inject(Router);
        vi.spyOn(router, 'navigate').mockResolvedValue(true);

        fixture = TestBed.createComponent(AppTopbar);
        fixture.detectChanges();
    });

    /** The button, found by its label the way a user finds it. */
    function button(): HTMLButtonElement {
        const match = Array.from(fixture.nativeElement.querySelectorAll('button')).find((element) =>
            (element as HTMLElement).textContent?.includes('Sign out')
        );
        expect(match, 'no button carries the sign-out label').toBeTruthy();
        return match as HTMLButtonElement;
    }

    it('tells the server, forgets the session and leaves the page', () => {
        button().click();
        fixture.detectChanges();

        // **The server first.** Without this call, the session row survives the sign-out and a tab
        // left open elsewhere goes on working.
        expect(logout).toHaveBeenCalledOnce();
        expect(session.isAuthenticated()).toBe(false);
        expect(router.navigate).toHaveBeenCalledWith(['/login'], { replaceUrl: true });
    });

    it('forgets the session even when the server does not answer', () => {
        // If a network failure left the user signed in in their browser, the button would lie
        // again — and this time only occasionally, which is worse.
        logout.mockReturnValue(throwError(() => new Error('network')));

        button().click();
        fixture.detectChanges();

        expect(session.isAuthenticated()).toBe(false);
        expect(router.navigate).toHaveBeenCalledWith(['/login'], { replaceUrl: true });
    });

    it('does not revoke twice when clicked twice', () => {
        // The button disables itself for the round trip, but the guard is in the method: a second
        // click fired before the render would otherwise send a second revocation, and the second
        // would fail against a session the first has just closed.
        const pending = new Subject<void>();
        logout.mockReturnValue(pending);

        fixture.componentInstance.signOut();
        fixture.componentInstance.signOut();
        fixture.detectChanges();

        expect(logout).toHaveBeenCalledOnce();
        expect(button().disabled).toBe(true);

        pending.next();
        pending.complete();
        expect(session.isAuthenticated()).toBe(false);
    });

    /**
     * **The accessible name, not the DOM's text.**
     *
     * The stylesheet hides these buttons' labels unconditionally
     * (`.layout-topbar-action span { display: none }`), so they had no name at all: a screen reader
     * announced three of them, indistinguishable, one of which ends the session.
     *
     * Nothing said so, and this file is one reason. It looks the button up by `textContent`, which
     * jsdom exposes because it applies no stylesheet — the test was reading a DOM nobody sees. The
     * browser did say so: the Playwright suite waited two minutes for a button named "Sign out",
     * three times over, from 15 September. This assertion is about what both of them look at.
     */
    it('names its three buttons for something other than the DOM', () => {
        const buttons: HTMLButtonElement[] = Array.from(
            (fixture.nativeElement as HTMLElement).querySelectorAll('.layout-topbar-menu button')
        );
        const named = buttons.map((element) => element.getAttribute('aria-label'));

        expect(named).toEqual(['Account', 'Password', 'Sign out']);
    });
});
