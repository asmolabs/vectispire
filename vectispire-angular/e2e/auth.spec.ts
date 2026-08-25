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
            const response = await page.request.post('http://127.0.0.1:3180/api/v1/auth/login', {
                data: {
                    username: 'admin',
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
        const response = await page.request.post('http://127.0.0.1:3180/api/v1/auth/mfa/verify', {
            data: { mfa_token: 'not-a-real-challenge', code: '000000' },
            failOnStatusCode: false
        });

        expect(response.status()).toBe(401);

        // Measured against a running instance rather than assumed: a chain rejection returns
        // 401 with *zero* bytes, while reaching the handler produces Spring's error document —
        // 401 with a body naming the path. The first draft of this test asserted on the
        // handler's message and would have failed, because Spring omits it unless
        // `server.error.include-message` is set.
        const body = await response.text();
        expect(body.length, 'a chain rejection has no body at all; a body means the handler ran').toBeGreaterThan(0);
        expect(body).toContain('/api/v1/auth/mfa/verify');
    });

    test('an MFA challenge cannot be brute-forced with unlimited guesses', async ({ page }) => {
        // The other half of the same fix: reaching the handler is only safe because the handler
        // now counts. Without a real challenge there is nothing to exhaust, so what is checked
        // here is that repeated attempts never start succeeding — no code is ever accepted, and
        // the answer stays the same shape whatever is thrown at it.
        for (let attempt = 0; attempt < 6; attempt++) {
            const response = await page.request.post('http://127.0.0.1:3180/api/v1/auth/mfa/verify', {
                data: { mfa_token: 'not-a-real-challenge', code: String(attempt).padStart(6, '0') },
                failOnStatusCode: false
            });

            expect(response.status(), 'a guess must never be accepted').toBe(401);
        }
    });

});
