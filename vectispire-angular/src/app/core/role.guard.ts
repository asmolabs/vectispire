import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { SessionStore } from './session.store';

/**
 * What a page needs, named after the server marker it mirrors.
 *
 * <p>Not a list of roles. A guard that spelled out `['SUPERUSER', 'ADMIN']` would be the second
 * list `Role` exists to avoid, one layer further out and with nothing to keep it in step.
 */
export type Need = 'administrator' | 'security-lead' | 'governance-read';

/**
 * Refuses a page the account cannot use, and says which page and why.
 *
 * <p><b>The server already refuses; this is about what the person sees.</b> Every route is guarded
 * server-side by one of seven markers, and two structural tests defend that — no data leaks by
 * typing a path. What did happen is that the component loaded, its first call answered 403, and
 * the screen showed "Could not load…" over an empty form. Thirty-five routes, no guard: the menu
 * hid the entries, it never barred them.
 *
 * <p><b>Signed out is not the same as not allowed.</b> An account with no session goes to the sign
 * in page — the interceptor would send it there on the first 401 anyway, and showing a refusal
 * first would tell somebody they lack a role when what they lack is a session.
 *
 * <p>The refusal keeps the sidebar, deliberately: somebody who took a wrong turn should see where
 * they may go instead of being dropped onto a bare page.
 */
export function requires(need: Need): CanActivateFn {
    return (route) => {
        const session = inject(SessionStore);
        const router = inject(Router);

        if (!session.isAuthenticated()) {
            return router.createUrlTree(['/login']);
        }
        if (allows(session, need)) {
            return true;
        }
        return router.createUrlTree(['/forbidden'], {
            queryParams: { need, page: route.routeConfig?.path ?? '' }
        });
    };
}

function allows(session: SessionStore, need: Need): boolean {
    switch (need) {
        case 'administrator':
            return session.isAdmin();
        case 'security-lead':
            return session.isSecurityLead();
        case 'governance-read':
            return session.canReadGovernance();
    }
}
