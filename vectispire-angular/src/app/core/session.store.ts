import { Injectable, computed, signal } from '@angular/core';

/** The server writes them in upper case (`user.entity.ts`). */
export const ADMIN_ROLES: readonly string[] = ['SUPERUSER', 'ADMIN'];
/** The roles that may **change** governance: the gate policy, the rule sets, the SIEM destination. */
export const SECURITY_LEAD_ROLES: readonly string[] = ['SUPERUSER', 'ADMIN', 'CISO'];
/**
 * The roles that may **read** it — a wider set, and the reason `AUDITOR` exists.
 *
 * Mirrors `@RequiresGovernanceRead` on the server. A screen that hid a read-only page behind
 * `isSecurityLead` would show an auditor an empty menu and a route that answers 200.
 */
export const GOVERNANCE_READER_ROLES: readonly string[] = ['SUPERUSER', 'ADMIN', 'CISO', 'AUDITOR'];
/**
 * The roles whose triage decision **settles** instead of going into an approval queue.
 *
 * <p><b>`SUPERUSER` is not among them, and that is the decision of 2 September.</b> That account is
 * the only one able to lift the four-eyes rule; if it could also decide under it, one would only
 * have to switch the rule off, settle alone, and switch it back on. The separation holds only if
 * the role governing the rule cannot act under it.
 */
export const TRIAGE_APPROVER_ROLES: readonly string[] = ['ADMIN', 'CISO', 'SECURITY_CHAMPION'];
/**
 * The role that governs the platform — the one that can lift a rule, and which for that reason
 * cannot act under it. See {@link TRIAGE_APPROVER_ROLES}.
 */
export const PLATFORM_GOVERNOR_ROLES: readonly string[] = ['SUPERUSER'];
/**
 * The roles that may **do** something — record a triage decision, open a ticket, run a review.
 *
 * Mirrors `@RequiresWriteAccount`. Deliberately wide: triaging is ordinary work, so an ordinary
 * user belongs here. `AUDITOR`, whose whole purpose is to look, sits outside — and so does
 * `SUPERUSER`, which governs the platform without acting on it (see `canCauseEffects`).
 */
export const EFFECT_CAUSING_ROLES: readonly string[] = ['ADMIN', 'CISO', 'SECURITY_CHAMPION', 'USER'];
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
    readonly isSecurityLead = computed(() => SECURITY_LEAD_ROLES.includes(this.role()));
    readonly canReadGovernance = computed(() => GOVERNANCE_READER_ROLES.includes(this.role()));
    readonly isSecurityChampion = computed(() => this.role() === 'SECURITY_CHAMPION');
    /**
     * Their triage decision **settles**. A signed-in account that lacks this may still triage —
     * the decision goes to the approval queue instead — which is why the two signals below are
     * separate and why a screen needs both to say the right thing.
     */
    readonly canApproveTriage = computed(() => TRIAGE_APPROVER_ROLES.includes(this.role()));
    /**
     * They can act, full stop.
     *
     * <p><b>False for two roles, and one of the two was missing.</b> The auditor, who comes to
     * observe, and the bootstrap account, which governs the platform without acting on it —
     * {@code Role.SUPERUSER} has carried {@code canCauseEffects = false} on the server since
     * governing was separated from acting. The screen, however, left it in the set: the bootstrap
     * account therefore saw the triage button, opened the dialog, and collected a 403 on save — the
     * broken screen all this work on roles existed to remove.
     */
    readonly canCauseEffects = computed(() => EFFECT_CAUSING_ROLES.includes(this.role()));
    /** They can change a rule of the platform, and not merely a setting. */
    readonly governsPlatform = computed(() => PLATFORM_GOVERNOR_ROLES.includes(this.role()));
    readonly isCiso = computed(() => this.role() === 'CISO');
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

    /**
     * The second factor has just been switched on or removed.
     *
     * <p>The token does not change — the current session stays the same — but the account screen
     * must state the new state, and reading it again through `/auth/me` would take a round trip for
     * information the response has just given.
     */
    setMfaEnabled(enabled: boolean): void {
        const user = this.user();
        if (user) this.user.set({ ...user, mfaEnabled: enabled });
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
