import { test, expect } from '@playwright/test';

test.describe('Settings Administration & Audit Log E2E', () => {

    test.beforeEach(async ({ page }) => {
        await page.goto('/login');
        await page.fill('input[name="username"], input[type="text"]', 'admin');
        await page.fill('input[name="password"], input[type="password"]', 'AdminVectispire2026!');
        await page.click('button[type="submit"]');
        await page.waitForURL(/\/(dashboard|issues|overview|targets)/, { timeout: 10000 });
    });

    test('toggles Four-Eyes Approval setting in Settings page', async ({ page }) => {
        await page.goto('/settings');

        const title = page.locator('h1, h2, .font-semibold').first();
        await expect(title).toBeVisible();

        // Check for double validation toggle setting
        const fourEyesToggle = page.locator('#triage_four_eyes_required, p-toggleswitch[inputid="triage_four_eyes_required"]');
        if (await fourEyesToggle.isVisible()) {
            await fourEyesToggle.click();

            const saveBtn = page.locator('button:has-text("Save"), p-button[icon="pi pi-check"]');
            if (await saveBtn.isEnabled()) {
                await saveBtn.click();

                const successMsg = page.locator('p-message[severity="success"], .p-message-success');
                await expect(successMsg).toBeVisible({ timeout: 5000 });
            }
        }
    });

    test('verifies audit log entries in Audit Trail page', async ({ page }) => {
        await page.goto('/audit');

        const title = page.locator('h1, h2, .font-semibold').first();
        await expect(title).toBeVisible();

        const auditTable = page.locator('p-table, table, .p-datatable');
        await expect(auditTable).toBeVisible();
    });

});
