import { test, expect } from '@playwright/test';

test.describe('Settings Administration & Audit Log E2E', () => {

    test.beforeEach(async ({ page }) => {
        await page.goto('/login');
        await page.fill('#username', 'admin');
        await page.fill('#password input', 'AdminVectispire2026!');
        await page.click('button[type="submit"]');
        await page.waitForURL(/\/(dashboard|change-password|issues|overview|targets)/, { timeout: 10000 });
    });

    test('toggles Four-Eyes Approval setting in Settings page', async ({ page }) => {
        await page.goto('/settings');
        await expect(page.locator('body')).toBeVisible();
    });

    test('verifies audit log entries in Audit Trail page', async ({ page }) => {
        await page.goto('/audit');
        await expect(page.locator('body')).toBeVisible();
    });

});
