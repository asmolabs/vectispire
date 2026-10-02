import { inject } from '@angular/core';
import { CanActivateFn, Router, UrlTree } from '@angular/router';
import { SessionStore } from './session.store';

/**
 * The shell opens to a session, and to a session that has changed its imposed password.
 *
 * <p><b>The shell used to mount for anybody.</b> The token lives in memory, so every reload
 * arrives signed out — and the layout rendered, its screen fired its calls unauthenticated, and
 * only the first 401 sent the browser to the sign-in page. The page asked for was forgotten on the
 * way, so a link someone had been handed landed on the dashboard after signing in.
 *
 * <p><b>`mustChangePassword` was enforced by the sign-in screen alone</b>, which routes such an
 * account to the change form. Nothing stopped that account from going anywhere else afterwards;
 * the flag exists precisely so that a provisioned password is not used for real work.
 *
 * <p>The server still refuses every call without a valid token; this is about what the person
 * sees, and about the calls that should not be made at all.
 */
export const signedIn: CanActivateFn = (_route, state) => {
    const session = inject(SessionStore);
    const router = inject(Router);

    if (!session.isAuthenticated()) {
        return signInPage(router, state.url);
    }
    if (session.mustChangePassword()) {
        return passwordChangePage(router, state.url);
    }
    return true;
};

/**
 * A session, and nothing more: for the password change itself, which the rule above sends to and
 * which must therefore not be subject to it.
 */
export const hasSession: CanActivateFn = (_route, state) => {
    const session = inject(SessionStore);
    return session.isAuthenticated() ? true : signInPage(inject(Router), state.url);
};

/**
 * The sign-in page, remembering where the person was going when there is somewhere to remember —
 * not the dashboard, where signing in goes anyway (and where `/` has been redirected by then).
 */
export function signInPage(router: Router, requested: string | undefined): UrlTree {
    return remembering(router, '/login', requested);
}

/**
 * The password change, remembering the page asked for in the same way: a provisioned account that
 * followed a link it had been handed used to change its password and land on the dashboard, the
 * link forgotten between the two screens.
 */
export function passwordChangePage(router: Router, requested: string | undefined): UrlTree {
    return remembering(router, '/change-password', requested);
}

function remembering(router: Router, page: string, requested: string | undefined): UrlTree {
    const returnUrl = safeReturnUrl(requested ?? null);
    return router.createUrlTree([page], returnUrl && returnUrl !== '/dashboard' ? { queryParams: { returnUrl } } : {});
}

/**
 * The address to go to after signing in, or null when it is not one of this application's pages.
 *
 * <p><b>The parameter arrives in a URL anybody can write</b>, so it is an open redirect unless it
 * is held to a path of this origin: `//host/…` and `/\host/…` are protocol-relative to a browser,
 * and `https:`/`javascript:` need no comment. The router would not follow them off-origin, but
 * this function is what keeps that true if a caller ever hands the value to `location`. The sign
 * in page itself is refused too, since returning there would loop — and so is the password change,
 * which would send a changed password back to the form that changed it — as is `/`, which has
 * nothing to remember.
 */
const LOOPING_PAGES = ['/login', '/change-password'];

export function safeReturnUrl(value: string | null): string | null {
    if (!value || !value.startsWith('/') || value.startsWith('//') || /[\\\s]/.test(value)) {
        return null;
    }
    const base = 'https://vectispire.invalid';
    let parsed: URL;
    try {
        parsed = new URL(value, base);
    } catch {
        return null;
    }
    if (parsed.origin !== base) return null;
    if (
        parsed.pathname === '/' ||
        LOOPING_PAGES.some((page) => parsed.pathname === page || parsed.pathname.startsWith(`${page}/`))
    ) {
        return null;
    }
    return value;
}
