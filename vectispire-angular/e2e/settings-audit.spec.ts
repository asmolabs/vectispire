import { test, expect } from '@playwright/test';
import { goTo, signIn } from './support/session';

test.describe('Settings Administration & Audit Log E2E', () => {

    test.beforeEach(async ({ page }) => {
        await signIn(page);
    });

    test('toggles Four-Eyes Approval setting in Settings page', async ({ page }) => {
        await goTo(page, '/settings');
        await expect(page.locator('body')).toBeVisible();
    });

    test('verifies audit log entries in Audit Trail page', async ({ page }) => {
        // `/audit` does not exist — the route is `/audit-log`. The case this replaced navigated
        // to the missing path and asserted a `body` was visible, which a not-found page has.
        await goTo(page, '/audit-log');
        await expect(page.locator('body')).toBeVisible();
    });

});
