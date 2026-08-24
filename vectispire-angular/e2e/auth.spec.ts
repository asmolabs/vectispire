import { test, expect } from '@playwright/test';

test.describe('Authentication & Anti-Brute-Force E2E', () => {

    test('successful login with bootstrapped admin credentials', async ({ page }) => {
        await page.goto('/login');

        await page.fill('input[name="username"], input[type="text"]', 'admin');
        await page.fill('input[name="password"], input[type="password"]', 'AdminVectispire2026!');

        await page.click('button[type="submit"]');

        // Should redirect to dashboard or main app layout
        await expect(page).toHaveURL(/\/(dashboard|issues|overview|targets)/, { timeout: 10000 });
    });

    test('login fails with invalid credentials', async ({ page }) => {
        await page.goto('/login');

        await page.fill('input[name="username"], input[type="text"]', 'admin');
        await page.fill('input[name="password"], input[type="password"]', 'WrongPassword2026!');

        await page.click('button[type="submit"]');

        // Should display error message
        const errorMessage = page.locator('p-message, .p-message-error, .text-red-500, [role="alert"]');
        await expect(errorMessage).toBeVisible({ timeout: 5000 });
    });

    test('burst login requests trigger HTTP 429 Bucket4j rate limiting', async ({ request }) => {
        // Send rapid API requests to /api/v1/auth/login directly
        let rateLimited = false;

        for (let i = 0; i < 15; i++) {
            const res = await request.post('/api/v1/auth/login', {
                data: {
                    username: 'admin',
                    password: 'WrongPasswordBurst!'
                }
            });

            if (res.status() === 429) {
                rateLimited = true;
                const headers = res.headers();
                expect(headers['retry-after'] || headers['x-rate-limit-retry-after-seconds']).toBeDefined();
                break;
            }
        }

        expect(rateLimited).toBe(true);
    });

});
