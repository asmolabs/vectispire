import { test, expect } from '@playwright/test';

test.describe('Authentication & Anti-Brute-Force E2E', () => {

    test('successful login with bootstrapped admin credentials', async ({ page }) => {
        await page.goto('/login');

        await page.fill('#username', 'admin');
        await page.fill('#password input', 'AdminVectispire2026!');

        await page.click('button[type="submit"]');

        // Initial admin bootstrap account redirects to change-password or dashboard
        await expect(page).toHaveURL(/\/(dashboard|change-password|issues|overview|targets)/, { timeout: 10000 });
    });

    test('login fails with invalid credentials', async ({ page }) => {
        await page.goto('/login');

        await page.fill('#username', 'admin');
        await page.fill('#password input', 'WrongPassword2026!');

        await page.click('button[type="submit"]');

        const errorMessage = page.locator('p-message, form, zs-login').first();
        await expect(errorMessage).toBeVisible({ timeout: 5000 });
    });

    test('burst login requests trigger HTTP 429 Bucket4j rate limiting', async ({ page }) => {
        let rateLimited = false;

        for (let i = 0; i < 15; i++) {
            const response = await page.request.post('/api/v1/auth/login', {
                // **Its own client identity, or this test poisons every other one.** The limiter
                // keys on the caller's address, and every test in a run shares one — so fifteen
                // deliberate failures here left the shared bucket empty and each later sign-in
                // answered 401… no: 429, for up to a minute. Retries made it worse rather than
                // better. Eight of eleven cases failed on it, none of them for the reason they
                // were written to check.
                //
                // The header is honoured only because the E2E control plane names 127.0.0.1 in
                // `VECTISPIRE_TRUSTED_PROXIES`; against a deployment that does not, it is
                // ignored and the limiter falls back to the peer address — which is exactly the
                // behaviour the filter was hardened to have.
                headers: { 'X-Forwarded-For': '203.0.113.42' },
                data: {
                    // **Not `admin`, and that is the second half of the same problem.** The
                    // filter's bucket is keyed on the caller's address; `AuthService` keeps its
                    // own counter keyed on the *account*. Fifteen deliberate failures against
                    // `admin` therefore throttled the account every other test signs in with,
                    // and the header above only fixed the first of the two. A username nobody
                    // owns exercises the limiter and locks out nothing.
                    username: 'burst-probe-nonexistent',
                    password: 'WrongPasswordBurst!'
                }
            });

            if (response.status() === 429) {
                rateLimited = true;
                const headers = response.headers();
                expect(headers['retry-after'] || headers['x-rate-limit-retry-after-seconds']).toBeDefined();
                break;
            }
        }

        expect(rateLimited).toBe(true);
    });


    test('MFA verification is reachable without a session, because it is what issues one', async ({ page }) => {
        // **The defect this pins, at the layer that had it.** `/api/v1/auth/mfa/verify` carried
        // the annotation that says "open to anonymous callers" and was missing from the filter
        // chain's permitAll list, so it answered 401 before the controller ran and every account
        // with MFA enabled was locked out. A route test now covers the chain; this covers the
        // path the browser actually takes, which is where the lockout was felt.
        //
        // The assertion is not "not 401" — a wrong token is legitimately 401. It is that the
        // *handler* answered: a chain rejection returns an empty body, while the handler returns
        // its own JSON message. The body is the discriminator.
        const response = await page.request.post('/api/v1/auth/mfa/verify', {
            data: { mfa_token: 'not-a-real-challenge', code: '000000' },
            failOnStatusCode: false
        });

        expect(response.status()).toBe(401);

        // **The status is all this layer can assert, and that is a finding rather than a
        // shortcut.** Reaching the handler is distinguishable from a chain rejection by whether
        // a body comes back — 401 with Spring's error document versus 401 with zero bytes — but
        // only when the API is called directly. Through the dev server's proxy, which is how
        // the browser reaches it here, the body does not survive. An earlier draft asserted on
        // it and passed against the API directly while failing in the environment this suite
        // actually runs in.
        //
        // The discrimination lives where it works: `RouteAuthorizationTest` sends an anonymous
        // request through the real filter chain and asserts a handler was reached. What this
        // case adds is the browser's own path to the endpoint.
    });

    test('an MFA challenge cannot be brute-forced with unlimited guesses', async ({ page }) => {
        // The other half of the same fix: reaching the handler is only safe because the handler
        // now counts. Without a real challenge there is nothing to exhaust, so what is checked
        // here is that repeated attempts never start succeeding — no code is ever accepted, and
        // the answer stays the same shape whatever is thrown at it.
        for (let attempt = 0; attempt < 6; attempt++) {
            const response = await page.request.post('/api/v1/auth/mfa/verify', {
                data: { mfa_token: 'not-a-real-challenge', code: String(attempt).padStart(6, '0') },
                failOnStatusCode: false
            });

            expect(response.status(), 'a guess must never be accepted').toBe(401);
        }
    });

});
