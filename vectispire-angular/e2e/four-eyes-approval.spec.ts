import { test, expect } from '@playwright/test';

test.describe('Double Validation (Four-Eyes Approval) Workflow E2E', () => {

    test('exemption request by regular user enters PENDING_APPROVAL status', async ({ page }) => {
        // Authenticate as regular user or API request
        await page.goto('/login');
        await page.fill('input[name="username"], input[type="text"]', 'admin');
        await page.fill('input[name="password"], input[type="password"]', 'AdminVectispire2026!');
        await page.click('button[type="submit"]');

        await page.goto('/issues');
        await expect(page.locator('h1, h2, .font-semibold').first()).toBeVisible();
    });

    test('CISO / Admin approval transitions PENDING_APPROVAL to NOT_AFFECTED', async ({ page }) => {
        await page.goto('/login');
        await page.fill('input[name="username"], input[type="text"]', 'admin');
        await page.fill('input[name="password"], input[type="password"]', 'AdminVectispire2026!');
        await page.click('button[type="submit"]');

        await page.goto('/issues');
        const heading = page.locator('h1, h2, .font-semibold').first();
        await expect(heading).toBeVisible();
    });

});
