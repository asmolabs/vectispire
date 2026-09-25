import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { LoginResponse, SignInMethods, MfaSetupResponse, MfaEnableResponse } from '../api.models';

/**
 * Signing in and out, the session, the password and the second factor.
 *
 * One stateless client per domain, named `*.api.ts` / `*Api` so that it is never mistaken for a
 * `*.service.ts` or a store holding state, and so that `scripts/check-dead-api-methods.mjs` knows
 * which files declare the API surface. No absolute URL: the development server proxies `/api`
 * (`proxy.conf.json`) and production serves both from one origin, which is what lets the CSP stay
 * on `connect-src 'self'`.
 */
@Injectable({ providedIn: 'root' })
export class AuthApi {
    private readonly http = inject(HttpClient);

    // No client_id: the server counts failures per resolved address, since a key the browser
    // chooses is one an attacker changes on every attempt.
    login(username: string, password: string): Observable<LoginResponse> {
        return this.http.post<LoginResponse>('/api/v1/auth/login', { username, password });
    }

    changePassword(currentPassword: string, newPassword: string): Observable<{ mustChangePassword: boolean }> {
        return this.http.post<{ mustChangePassword: boolean }>('/api/v1/auth/change-password', {
            current_password: currentPassword,
            new_password: newPassword
        });
    }

    logout(): Observable<void> {
        return this.http.delete<void>('/api/v1/auth/session');
    }

    signInMethods(): Observable<SignInMethods> {
        return this.http.get<SignInMethods>('/api/v1/auth/methods');
    }

    /**
     * Trades the one-time hand-off cookie for the session it stands for.
     *
     * <p>`withCredentials` is what makes it work: the cookie is host-only and would not be sent
     * otherwise, and the sign-on would succeed while the application still showed a login screen.
     */
    completeSignIn(): Observable<LoginResponse> {
        return this.http.post<LoginResponse>('/api/v1/auth/session/exchange', {}, { withCredentials: true });
    }

    verifyMfa(mfaToken: string, code: string): Observable<LoginResponse> {
        return this.http.post<LoginResponse>('/api/v1/auth/mfa/verify', { mfa_token: mfaToken, code });
    }

    setupMfa(): Observable<MfaSetupResponse> {
        return this.http.post<MfaSetupResponse>('/api/v1/auth/mfa/setup', {});
    }

    enableMfa(secret: string, code: string): Observable<MfaEnableResponse> {
        return this.http.post<MfaEnableResponse>('/api/v1/auth/mfa/enable', { secret, code });
    }

    disableMfa(code: string): Observable<{ mfaEnabled: boolean }> {
        return this.http.post<{ mfaEnabled: boolean }>('/api/v1/auth/mfa/disable', { code });
    }
}
