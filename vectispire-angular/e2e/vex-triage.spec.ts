import { test, expect } from '@playwright/test';

test.describe('VEX Triage & Backlog Management E2E', () => {

    test.beforeEach(async ({ page }) => {
        // Log in as admin
        await page.goto('/login');
        await page.fill('input[name="username"], input[type="text"]', 'admin');
        await page.fill('input[name="password"], input[type="password"]', 'AdminVectispire2026!');
        await page.click('button[type="submit"]');
        await page.waitForURL(/\/(dashboard|issues|overview|targets)/, { timeout: 10000 });
    });

    test('navigates to issues backlog and views issue details', async ({ page }) => {
        await page.goto('/issues');

        // Check page title and table presence
        const heading = page.locator('h1, h2, .font-semibold');
        await expect(heading.first()).toBeVisible();

        const table = page.locator('p-table, table, .p-datatable');
        await expect(table).toBeVisible();
    });

    test('applies VEX triage status on a single vulnerability issue', async ({ page }) => {
        await page.goto('/issues');

        const firstRow = page.locator('tbody tr').first();
        if (await firstRow.isVisible()) {
            await firstRow.click();

            // Look for triage button or action drawer
            const triageBtn = page.locator('button:has-text("Triage"), p-button:has-text("Triage")');
            if (await triageBtn.isVisible()) {
                await triageBtn.click();

                // Select NOT_AFFECTED or FIXED
                const selectJustification = page.locator('p-select, select').first();
                if (await selectJustification.isVisible()) {
                    await selectJustification.click();
                }

                const submitBtn = page.locator('button:has-text("Save"), button:has-text("Apply"), button[type="submit"]');
                if (await submitBtn.isVisible()) {
                    await submitBtn.click();
                }
            }
        }
    });

});
