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

export async function signIn(page: Page): Promise<void> {
    const accepted = (await attempt(page, BOOTSTRAP_PASSWORD)) || (await attempt(page, E2E_PASSWORD));
    expect(accepted, 'neither the bootstrap nor the rotated password was accepted').toBe(true);

    if (!onChangePassword(page)) {
        return;
    }

    await rotate(page);

    // **Signed in again, because the change revokes every session the account had** — including
    // the one that just made it. Without this the helper returns on a page that is about to
    // redirect, and the case that follows fails against the sign-in screen for a reason that has
    // nothing to do with what it was testing.
    const afterRotation = await attempt(page, E2E_PASSWORD);
    expect(afterRotation, 'the rotated password was refused right after being set').toBe(true);
}

function onChangePassword(page: Page): boolean {
    return new URL(page.url()).pathname.startsWith('/change-password');
}

/** True when the credentials were accepted, whatever the screen we landed on. */
async function attempt(page: Page, password: string): Promise<boolean> {
    await page.goto('/login');
    await page.fill('#username', 'admin');
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

/** The sidebar wording for the paths the suites visit. */
const LINKS: Record<string, string> = {
    '/issues': 'Issues',
    '/licenses': 'Open Source Licenses',
    '/settings': 'Settings',
    '/audit-log': 'Audit log'
};
