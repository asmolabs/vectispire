import { HttpErrorResponse, HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { Router } from '@angular/router';
import { catchError, throwError } from 'rxjs';
import { SessionStore } from './session.store';

/** The calls where a 401 is not a verdict about the session. */
const NOT_A_SESSION_VERDICT = [
    // Nothing pending to complete, which is the ordinary answer on a page nobody signed on
    // from — not a verdict on a session that may well be open.
    '/api/v1/auth/session/exchange',
    '/api/v1/auth/change-password'
];

/**
 * Puts the token on every request, and handles the 401 in one place.
 *
 * **A 401 closes the session and returns to the sign-in screen.** The server alone judges a
 * token's validity — it may have revoked it, or the session may have expired on inactivity —
 * and letting each screen guess would produce as many interpretations as there are screens.
 *
 * A **403** is deliberately not handled here: it means "you are signed in but this is not for
 * you", and signing somebody out because they clicked an administration link would be a
 * disproportionate response to a navigation mistake.
 *
 * **One exception, and only one**: the password change. There, a 401 means "the current
 * password is wrong", not "your session expired" — the general rule signed people out over a
 * typo, which nobody sees until they make one.
 */
export const authInterceptor: HttpInterceptorFn = (request, next) => {
    const session = inject(SessionStore);
    const router = inject(Router);

    const token = session.bearer();
    const authorized = token ? request.clone({ setHeaders: { Authorization: `Bearer ${token}` } }) : request;

    return next(authorized).pipe(
        catchError((error: HttpErrorResponse) => {
            const aboutTheSession = !NOT_A_SESSION_VERDICT.some((path) => request.url.startsWith(path));
            if (error.status === 401 && aboutTheSession) {
                session.close();
                // `replaceUrl`: the page that failed must not stay in the history, or the
                // back button lands on an empty screen.
                void router.navigate(['/login'], { replaceUrl: true });
            }
            return throwError(() => error);
        })
    );
};
