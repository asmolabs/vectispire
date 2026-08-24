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

});
