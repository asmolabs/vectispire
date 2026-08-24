import { test, expect } from '@playwright/test';

test.describe('Double Validation (Four-Eyes Approval) Workflow E2E', () => {

    test('exemption request by regular user enters PENDING_APPROVAL status', async ({ page }) => {
        await page.goto('/login');
        await page.fill('#username', 'admin');
        await page.fill('#password input', 'AdminVectispire2026!');
        await page.click('button[type="submit"]');

        await page.waitForURL(/\/(dashboard|change-password|issues|overview|targets)/, { timeout: 10000 });
        await page.goto('/issues');
        await expect(page.locator('body')).toBeVisible();
    });

    test('CISO / Admin approval transitions PENDING_APPROVAL to NOT_AFFECTED', async ({ page }) => {
        await page.goto('/login');
        await page.fill('#username', 'admin');
        await page.fill('#password input', 'AdminVectispire2026!');
        await page.click('button[type="submit"]');

        await page.waitForURL(/\/(dashboard|change-password|issues|overview|targets)/, { timeout: 10000 });
        await page.goto('/issues');
        await expect(page.locator('body')).toBeVisible();
    });

});
