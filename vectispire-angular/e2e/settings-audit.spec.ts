import { resetLoginThrottle } from './support/fixture';
import { test, expect } from '@playwright/test';
import { goTo, signIn } from './support/session';

test.describe('Settings Administration & Audit Log E2E', () => {

    // The brute-force budget is global and narrow: without this, the case that receives the 429
    // is not the one that spent it. See `resetLoginThrottle`.
    test.beforeEach(() => resetLoginThrottle());

    test.beforeEach(async ({ page }) => {
        await signIn(page);
    });

    test('four-eyes approval is visible in the settings, and its name is readable', async ({ page }) => {
        // **This case was called "toggles Four-Eyes Approval" and toggled nothing**: it navigated
        // and checked that a `body` was visible — which a 403 error screen has too, and so does a
        // guard redirect. It could not fail. The neighbouring case's comment denounces exactly this
        // defect, fixed there and left here.
        await goTo(page, '/settings');

        // **Under "Governance", and the tab had to be created.** The rule was on none of them:
        // `isSectionVisible` was a per-tab allow list ending in a `return false`, and three
        // sections — this one and target visibility among them — showed nowhere. So this case was
        // looking for a label no screen rendered.
        await page.getByRole('button', { name: /governance|gouvernance/i }).click();
        await expect(page.getByText(/double validation|four.eyes/i).first())
            .toBeVisible({ timeout: 15000 });
    });

    test('verifies audit log entries in Audit Trail page', async ({ page }) => {
        // `/audit` does not exist — the route is `/audit-log`. The case this replaced navigated
        // to the missing path and asserted a `body` was visible, which a not-found page has.
        await goTo(page, '/audit-log');
        // Une assertion sur le contenu et non sur l'existence d'un `body` : la page d'erreur en a
        // un, la page introuvable aussi.
        await expect(page.getByRole('heading', { name: /journal|audit/i }).first())
            .toBeVisible({ timeout: 15000 });
    });

});
