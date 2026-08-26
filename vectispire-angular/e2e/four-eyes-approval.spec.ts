import { test, expect } from '@playwright/test';
import { goTo, signIn } from './support/session';

/**
 * **These two cases still assert only that a `body` is visible**, which passes on an error page.
 * They were migrated to {@link signIn} because the bootstrap password change made them unable to
 * reach `/issues` at all, but their assertions were left as they were: writing the four-eyes
 * workflow properly needs a second account and an exemption to approve, which is a fixture this
 * change does not build. Recorded as owed rather than quietly counted as coverage.
 */
test.describe('Double Validation (Four-Eyes Approval) Workflow E2E', () => {

    test('exemption request by regular user enters PENDING_APPROVAL status', async ({ page }) => {
        await signIn(page);
        await goTo(page, '/issues');
        await expect(page.locator('body')).toBeVisible();
    });

    test('CISO / Admin approval transitions PENDING_APPROVAL to NOT_AFFECTED', async ({ page }) => {
        await signIn(page);
        await goTo(page, '/issues');
        await expect(page.locator('body')).toBeVisible();
    });

});
