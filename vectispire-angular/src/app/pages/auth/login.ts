import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { ButtonModule } from '@openng/optimus-ui/button';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { PasswordModule } from '@openng/optimus-ui/password';
import type { SignInMethods } from '../../core/api.models';
import { AuthApi } from '@/app/core/api/auth.api';
import { SessionStore } from '@/app/core/session.store';
import { I18nService } from '@/app/core/i18n/i18n.service';

/**
 * The sign-in screen.
 *
 * **No default credential is displayed**, unlike the Reflex version. The bootstrap account
 * carries `mustChangePassword`, which is the correct way to say "change your password" without
 * writing down what it currently is.
 *
 * The error message does not distinguish "unknown account" from "wrong password" — the API does
 * not distinguish them either, and separating them would hand the list of existing accounts to
 * whoever probes it. A rate-limiter block, on the other hand, is announced: that is something
 * the person needs to know, so that they know waiting is enough.
 */
import { CommonModule } from '@angular/common';
import { TranslatePipe } from '@/app/core/i18n/translate.pipe';
import { BrandingService } from '@/app/core/branding.service';

@Component({
    selector: 'zs-login',
    standalone: true,
    imports: [CommonModule, FormsModule, ButtonModule, InputTextModule, PasswordModule, MessageModule, TranslatePipe],
    templateUrl: './login.html'
})
export class Login {
    private readonly authApi = inject(AuthApi);
    private readonly session = inject(SessionStore);
    private readonly router = inject(Router);
    private readonly i18n = inject(I18nService);
    readonly branding = inject(BrandingService);

    username = '';
    password = '';
    mfaCode = '';
    readonly loading = signal(false);
    readonly error = signal<string | null>(null);
    readonly mfaRequired = signal(false);
    readonly mfaToken = signal<string | null>(null);

    /** Null until the server has said which ways in this deployment accepts. */
    readonly methods = signal<SignInMethods | null>(null);

    constructor() {
        this.authApi.signInMethods().subscribe({
            next: (methods) => this.methods.set(methods),
            // A deployment that cannot answer offers the password form alone, which is the
            // conservative default: showing a button that leads nowhere is worse than hiding one.
            error: () => this.methods.set(null)
        });

        // A refused or failed sign-on comes back here as a redirect, and its reason travels in
        // the query rather than being lost with the tab that was replaced.
        const parameters = new URLSearchParams(window.location.search);
        if (parameters.get('sso') === 'complete') {
            this.completeSignIn();
        } else if (parameters.get('sso') === 'refused') {
            this.error.set(parameters.get('reason') ?? this.i18n.t('auth.error_sso_refused'));
        } else if (parameters.get('sso') === 'failed') {
            this.error.set(this.i18n.t('auth.error_sso_failed'));
        }
    }

    /**
     * Picks up the session the sign-on just produced.
     *
     * <p>The hand-off cookie is {@code HttpOnly}, so this screen cannot see it and does not try:
     * it asks the server, which reads it once and deletes it. A refusal here is not a failed
     * sign-on but an expired one — sixty seconds is the whole life of that cookie.
     */
    private completeSignIn(): void {
        this.loading.set(true);
        this.authApi.completeSignIn().subscribe({
            next: (response) => {
                if (response.token && response.user) {
                    this.session.open(response.token, response.user);
                    this.loading.set(false);
                    void this.router.navigate([response.user.mustChangePassword ? '/change-password' : '/dashboard'],
                        { replaceUrl: true });
                }
            },
            error: () => {
                this.loading.set(false);
                this.error.set(this.i18n.t('auth.error_sso_incomplete'));
            }
        });
    }

    /**
     * Leaves the application for the provider.
     *
     * <p>A real navigation, and the one place one is right: this is not a request for data, it is
     * handing the browser to another origin so it can come back with an authorization code. The
     * session that results is fetched afterwards by the exchange.
     */
    signInWithProvider(): void {
        window.location.href = '/oauth2/authorization/oidc';
    }

    cancelMfa(): void {
        this.mfaRequired.set(false);
        this.mfaToken.set(null);
        this.mfaCode = '';
        this.error.set(null);
    }

    verifyMfa(): void {
        if (this.loading() || !this.mfaToken() || !this.mfaCode.trim()) return;
        this.loading.set(true);
        this.error.set(null);

        this.authApi.verifyMfa(this.mfaToken()!, this.mfaCode.trim()).subscribe({
            next: (response) => {
                if (response.token && response.user) {
                    this.session.open(response.token, response.user);
                    void this.router.navigate([response.user.mustChangePassword ? '/change-password' : '/dashboard']);
                }
            },
            error: (response: { status: number; error?: { message?: string } }) => {
                this.loading.set(false);
                this.error.set(response.error?.message ?? this.i18n.t('auth.error_mfa_invalid'));
            }
        });
    }

    submit(): void {
        if (this.mfaRequired()) {
            this.verifyMfa();
            return;
        }

        if (this.loading()) return;
        this.loading.set(true);
        this.error.set(null);

        this.authApi.login(this.username, this.password, clientId()).subscribe({
            next: (response) => {
                if (response.mfa_required) {
                    this.loading.set(false);
                    this.mfaRequired.set(true);
                    this.mfaToken.set(response.mfa_token ?? null);
                    return;
                }

                if (response.token && response.user) {
                    this.session.open(response.token, response.user);
                    // Un compte de provisionnement va d'abord changer son mot de passe : le
                    // laisser atteindre le reste viderait le drapeau de son sens.
                    void this.router.navigate([response.user.mustChangePassword ? '/change-password' : '/dashboard']);
                }
            },
            error: (response: { status: number; error?: { message?: string; retryAfterSeconds?: number } }) => {
                this.loading.set(false);
                const retryAfter = response.error?.retryAfterSeconds;
                if (retryAfter) {
                    this.error.set(this.i18n.t('auth.error_too_many_attempts', { minutes: Math.ceil(retryAfter / 60) }));
                } else if (response.status === 401) {
                    this.error.set(this.i18n.t('auth.error_invalid_credentials'));
                } else {
                    // An unreachable or failing server used to display "Invalid credentials",
                    // which sends somebody hunting for the right password while the real fault
                    // is elsewhere. Seen by trying it, not by reading it.
                    this.error.set(
                        response.status === 0
                            ? this.i18n.t('auth.error_server_unreachable')
                            : this.i18n.t('auth.error_server_status', { status: response.status })
                    );
                }
            }
        });
    }
}

/**
 * Identifies this browser for the rate limiter's second counter.
 *
 * Persisted, because an identifier drawn afresh on every load would make that counter useless —
 * and it is precisely the one that stops an attacker sweeping the account list from a single
 * machine. It is not a secret: losing it gives nobody anything, it only makes the limiter more
 * forgiving.
 */
function clientId(): string {
    const key = 'vectispire.client';
    // Storage can refuse outright — a private window, blocked site data — and an uncaught throw
    // here made sign-in itself fail. Without it the identifier is simply not kept: the limiter
    // becomes more forgiving for this browser, which is the stated cost of losing it anyway.
    try {
        let value = localStorage.getItem(key);
        if (!value) {
            value = crypto.randomUUID();
            localStorage.setItem(key, value);
        }
        return value;
    } catch {
        return crypto.randomUUID();
    }
}
