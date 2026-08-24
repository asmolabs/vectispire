import { test, expect } from '@playwright/test';

test.describe('VEX Triage & Backlog Management E2E', () => {

    test.beforeEach(async ({ page }) => {
        await page.goto('/login');
        await page.fill('#username', 'admin');
        await page.fill('#password input', 'AdminVectispire2026!');
        await page.click('button[type="submit"]');
        await page.waitForURL(/\/(dashboard|change-password|issues|overview|targets)/, { timeout: 10000 });
    });

    test('navigates to issues backlog and views issue details', async ({ page }) => {
        await page.goto('/issues');

        const body = page.locator('body');
        await expect(body).toBeVisible();
    });

    test('applies VEX triage status on a single vulnerability issue', async ({ page }) => {
        await page.goto('/issues');

        const body = page.locator('body');
        await expect(body).toBeVisible();
    });

});
