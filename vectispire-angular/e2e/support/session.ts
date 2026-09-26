import { expect, type Page } from '@playwright/test';

/**
 * Signing in, including the password change the bootstrap account demands.
 *
 * **Why this exists.** A bootstrapped `SUPERUSER` is created with
 * `mustChangePassword` set, so the sign-in lands on `/change-password` and every guarded page
 * bounces back. Four of the five browser suites navigate straight to a guarded page, so every one
 * of them was looking at the sign-in screen and asserting whatever it could still see. Nobody
 * could know: the browser suite has never completed a run — the CI image was thirteen minor
 * versions behind Playwright and no browser launched at all.
 *
 * **Idempotent across runs on purpose.** The change is a one-way door and the SQLite file survives
 * a local re-run, so this tries the bootstrap password and falls back to the rotated one. A helper
 * that only worked on a fresh database would pass in CI and fail on the second local run, which is
 * the worst of both.
 */
export const BOOTSTRAP_PASSWORD = 'AdminVectispire2026!';

/** Rotated to on first use. Different from the bootstrap value, which the server refuses to reuse. */
export const E2E_PASSWORD = 'E2eVectispire2026!';

/**
 * The password that worked, per account, so it is never rediscovered.
 *
 * <p><b>Every failed attempt is counted by the server, and the budget is five.</b>
 * {@code LoginThrottle} blocks an account after five failures inside a fifteen-minute window, and
 * those are compile-time constants. {@code VECTISPIRE_SECURITY_LOGIN_ATTEMPTS_PER_WINDOW}, which
 * the nightly sets to 200, raises the per-address bucket and not this one. The helpers therefore
 * tried two passwords at every sign-in — one guaranteed failure per case — and a suite of
 * seventeen cases spent {@code admin}'s budget long before the end. That is the origin of the
 * "neither password was accepted" failures that struck cases unrelated to one another.
 *
 * <p>The cache lives in the worker's process: the first sign-in searches, the ones after it know.
 */
const known = new Map<string, string>();

async function signInWith(page: Page, username: string, ...candidates: string[]): Promise<boolean> {
    const remembered = known.get(username);
    if (remembered && (await attempt(page, remembered, username))) {
        return true;
    }

    for (const candidate of candidates) {
        if (candidate !== remembered && (await attempt(page, candidate, username))) {
            known.set(username, candidate);
            return true;
        }
    }
    return false;
}

export async function signIn(page: Page): Promise<void> {
    const accepted = await signInWith(page, 'admin', BOOTSTRAP_PASSWORD, E2E_PASSWORD);
    expect(accepted, 'neither the bootstrap nor the rotated password was accepted').toBe(true);

    if (!onChangePassword(page)) {
        return;
    }

    await rotate(page);

    // **Signed in again, because the change revokes every session the account had** — including
    // the one that just made it. Without this the helper returns on a page that is about to
    // redirect, and the case that follows fails against the sign-in screen for a reason that has
    // nothing to do with what it was testing.
    known.set('admin', E2E_PASSWORD);
    const afterRotation = await attempt(page, E2E_PASSWORD);
    expect(afterRotation, 'the rotated password was refused right after being set').toBe(true);
}

function onChangePassword(page: Page): boolean {
    return new URL(page.url()).pathname.startsWith('/change-password');
}

/** True when the credentials were accepted, whatever the screen we landed on. */
async function attempt(page: Page, password: string, username = 'admin'): Promise<boolean> {
    await page.goto('/login');
    await page.fill('#username', username);
    await page.fill('#password input', password);
    await page.click('button[type="submit"]');

    await page.waitForURL(/\/(dashboard|change-password|issues|overview|targets)/, { timeout: 15_000 }).catch(() => {});
    return !new URL(page.url()).pathname.startsWith('/login');
}

async function rotate(page: Page): Promise<void> {
    await page.fill('#current input', BOOTSTRAP_PASSWORD);
    await page.fill('#next input', E2E_PASSWORD);
    await page.fill('#confirm input', E2E_PASSWORD);
    await page.click('button[type="submit"]');

    // Left the screen, so the change was accepted. Asserted rather than assumed: a refusal here
    // leaves the form in place, and every case after it would fail on something unrelated.
    await expect(page).not.toHaveURL(/\/change-password/, { timeout: 15_000 });
}

/**
 * Navigates inside the running application, rather than reloading it.
 *
 * <p><b>`page.goto` signs you out, and that is the product working as designed.</b> The session
 * token lives in memory and deliberately not in `localStorage`, so that an injected script cannot
 * read it — the store says so in its own comment. A full navigation drops it, and the guard sends
 * the browser back to the sign-in screen.
 *
 * <p>Every browser case in this repository used `page.goto` after signing in, so every one of them
 * was asserting against the sign-in screen. Four of them asserted only that a `body` was visible,
 * which is true there, so nothing ever said so.
 */
export async function goTo(page: Page, path: string): Promise<void> {
    await page.getByRole('link', { name: LINKS[path] ?? path, exact: false }).first().click();
    await expect(page).toHaveURL(new RegExp(`${path.replace('/', '\\/')}(\\?|$)`), { timeout: 15_000 });
}

/**
 * The button that offers a triage, whatever label it carries.
 *
 * <p><b>Written here because it was written four times.</b> The label depends on the role —
 * "Triage" when the decision settles, "Send for approval" when it goes into a queue — and it has
 * just come to depend on the language too, by going through the dictionary. All four copies were
 * hard-coded French; three suites therefore went blind at once, and an assertion of "no triage
 * button" that finds nothing because it is looking for the wrong word says nothing at all.
 */
export const TRIAGE_BUTTON = /^(Triage|Send for approval)( \(\d+\))?$/;

/** The button that confirms the triage dialog, whose label follows the same rule. */
export const TRIAGE_SAVE = /save|enregistrer|approval|approbation/i;

/** The sidebar wording for the paths the suites visit. */
const LINKS: Record<string, string> = {
    '/issues': 'Issues',
    '/licenses': 'Open Source Licenses',
    '/settings': 'Settings',
    '/audit-log': 'Audit log',
    '/attestation': 'Attestation',
    '/remediation': 'Remediation',
    '/solutions': 'Solutions & projects',

    // **The six evidence screens, reached through the sidebar like any other.** That is
    // deliberately a reader's path: a page whose route answers but that no menu entry mentions is
    // a page nobody will open, and a direct `page.goto` cannot see the difference.
    '/exceptions': 'Exceptions register',
    '/gate-verdicts': 'Verdict register',
    '/remediation-delays': 'Time to fix',
    '/soa': 'Statement of applicability',
    '/certified-scope': 'Certified scope',
    '/compliance-history': 'Compliance progression',

    // The coverage banner has no screen of its own: it sits on the ones where its absence would
    // produce a false conclusion. This is the only one of the two with a menu entry.
    '/rule-sets': 'Semgrep rules'
};

/** The role accounts' password, and the one the first use rotates it to. */
export const ROLE_PASSWORD = 'RoleVectispire2026!';
export const ROLE_PASSWORD_ROTATED = 'RoleVectispire2026Bis!';

/**
 * Signs in with an account of the requested role, creating it where needed.
 *
 * <p><b>Why this detour rather than the bootstrap account.</b> Bootstrap creates a
 * {@code SUPERUSER}, and that role governs the platform without acting on it: it does not triage,
 * does not open a ticket, does not launch a review. The suites that triage were therefore signing
 * in with the one account that may not — they passed because they stub the triage API, which is
 * another way of not finding out. The detour reproduces what a real installation does: the root
 * account creates the working accounts.
 *
 * <p><b>The token is passed by hand, and it has to be.</b> `page.request` shares the browser's
 * cookies, but Vectispire's session lives in memory rather than in a cookie — a deliberate choice
 * of `SessionStore`. Without an explicit header the creation call leaves with no credential, and
 * the server is right to refuse it.
 *
 * <p><b>And the account created must change its password</b>, like the bootstrap one. The rotation
 * is attempted once and then both passwords are tried, so that a local rerun against the same
 * database behaves like the first.
 */
export async function signInAs(page: Page, role: 'ADMIN' | 'CISO' | 'AUDITOR' | 'USER'): Promise<string> {
    const username = `e2e-${role.toLowerCase()}`;

    // **The short path first.** The account survives from one run to the next: past the first, the
    // whole detour comes down to a sign-in. Doing it anyway cost five navigations per case — the
    // bootstrap sign-in, its rotation, the creation, then the account's sign-in — and pushed past
    // the timeout in the suites that call this from a `beforeEach`.
    if (known.has(username) && (await attempt(page, known.get(username)!, username))) {
        return username;
    }
    if (!known.has(username) && (await attempt(page, ROLE_PASSWORD_ROTATED, username))) {
        known.set(username, ROLE_PASSWORD_ROTATED);
        return username;
    }

    await signIn(page);
    const token = await tokenFor(page, 'admin', E2E_PASSWORD, BOOTSTRAP_PASSWORD);
    // **The refusal is not asserted, and the sign-in that follows is.** The account may already
    // exist — a local rerun against the same database, or another case in the same file that
    // created it first. What matters is not that this call succeeds but that an account of this
    // role exists and can sign in, and it is the next assertion that says so.
    await page.request.post('/api/v1/users', {
        headers: { Authorization: `Bearer ${token}` },
        data: { username, password: ROLE_PASSWORD, role, display_name: username }
    });

    const accepted = await signInWith(page, username, ROLE_PASSWORD, ROLE_PASSWORD_ROTATED);
    expect(accepted, `neither password was accepted for ${username}`).toBe(true);

    if (new URL(page.url()).pathname.startsWith('/change-password')) {
        await page.fill('#current input', ROLE_PASSWORD);
        await page.fill('#next input', ROLE_PASSWORD_ROTATED);
        await page.fill('#confirm input', ROLE_PASSWORD_ROTATED);
        await page.click('button[type="submit"]');
        await expect(page).not.toHaveURL(/\/change-password/, { timeout: 15_000 });

        // The change revokes every session of the account, including the one that just made it —
        // the same reason as for bootstrap.
        known.set(username, ROLE_PASSWORD_ROTATED);
        const again = await attempt(page, ROLE_PASSWORD_ROTATED, username);
        expect(again, `the rotated password was refused immediately after being set`).toBe(true);
    }

    return username;
}

/** A bearer token, obtained through the API: the only way to authenticate `page.request`. */
async function tokenFor(page: Page, username: string, ...passwords: string[]): Promise<string> {
    // **The status codes are kept for the failure message.** "No password produced a token" does
    // not tell a wrong password apart from a 429 out of the attempt limiter or a 502 out of the
    // proxy while the development server recompiles — three causes with three different fixes, two
    // of which have nothing to do with the test.
    const refusals: number[] = [];
    for (const password of passwords) {
        const response = await page.request.post('/api/v1/auth/login', { data: { username, password } });
        if (response.ok()) {
            const token = (await response.json())['token'];
            if (token) return token;
        }
        refusals.push(response.status());
    }
    throw new Error(
        `no password produced a token for ${username} (responses: ${refusals.join(', ')})`);
}
