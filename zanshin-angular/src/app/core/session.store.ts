import { Injectable, computed, signal } from '@angular/core';

/** The server writes them in upper case (`user.entity.ts`). */
export const ADMIN_ROLES: readonly string[] = ['SUPERUSER', 'ADMIN'];
import { AuthenticatedUser } from './api.models';

/**
 * The session, browser side.
 *
 * **The token lives in memory, not in `localStorage`.** A deliberate departure from the Reflex
 * version, which kept its client token there: anything in `localStorage` is readable by every
 * script on the page, and therefore exfiltrable through the smallest XSS, and it outlives the
 * tab indefinitely.
 *
 * The price is real and accepted: reloading the page signs you out. The clean remedy is an
 * `HttpOnly` cookie set by the server, which the browser sends and JavaScript cannot read — to
 * be done once the deployment is settled, the API already accepting a bearer token.
 */
@Injectable({ providedIn: 'root' })
export class SessionStore {
    private readonly token = signal<string | null>(null);
    readonly user = signal<AuthenticatedUser | null>(null);

    readonly isAuthenticated = computed(() => this.token() !== null);
    readonly role = computed(() => this.user()?.role ?? '');

    /**
     * The administrator role vocabulary, **written once**.
     *
     * It lived in the menu, and the repositories screen had copied a variant of it comparing
     * against a lowercase `'admin'` — so always false. A duplicated role comparison is a
     * duplicated access control: it will diverge, and the divergence reads either as a missing
     * button or as a button that answers 403.
     */
    readonly isAdmin = computed(() => ADMIN_ROLES.includes(this.role()));
    /** The account must change its password before reaching anything else. */
    readonly mustChangePassword = computed(() => this.user()?.mustChangePassword ?? false);

    /** After a successful change: the requirement lifts without signing in again, the current
     *  session having deliberately survived on the server. */
    clearMustChangePassword(): void {
        const user = this.user();
        if (user) this.user.set({ ...user, mustChangePassword: false });
    }

    open(token: string, user: AuthenticatedUser): void {
        this.token.set(token);
        this.user.set(user);
    }

    close(): void {
        this.token.set(null);
        this.user.set(null);
    }

    /** Read by the interceptor, and by nothing else. */
    bearer(): string | null {
        return this.token();
    }
}
