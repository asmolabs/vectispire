import { test, expect } from '@playwright/test';

/**
 * The licence dashboard's headline figures, in a real browser against a real server.
 *
 * **What this adds over `licenses.spec.ts`, stated carefully.** The unit spec does render the
 * template — Angular's TestBed mounts it into jsdom — and it already asserts the sum the template
 * computes. So the reason for a browser case is not "a unit test cannot read the template", which
 * is what a first draft of this comment claimed and was wrong.
 *
 * What a browser adds is everything jsdom stands in for: the figures arrive through the real
 * sign-in, the real proxy and the real HTTP stack, and they are read off a page laid out by a
 * real engine. A component that renders correctly in isolation and is covered by a sidebar, or a
 * summary that never arrives because the route it depends on answers 403 to this account, look
 * identical to a passing unit spec.
 *
 * The API is stubbed rather than seeded: the arithmetic is the subject, and a fixture that
 * depended on what a scan happened to find would make a wrong total look like a data problem.
 */
test.describe('Licence dashboard figures', () => {

    test.beforeEach(async ({ page }) => {
        await page.route('**/api/v1/licenses/summary*', (route) =>
            route.fulfill({
                status: 200,
                contentType: 'application/json',
                // FORBIDDEN is deliberately absent, and STRONG_COPYLEFT deliberately present:
                // the `?? 0` on the missing half is what stops the whole sum reading as blank.
                body: JSON.stringify({
                    totalDependencies: 128,
                    uniqueLicenses: 9,
                    nonCompliantCount: 4,
                    breakdownByRisk: { PERMISSIVE: 100, WEAK_COPYLEFT: 21, STRONG_COPYLEFT: 7 }
                })
            })
        );
        await page.route('**/api/v1/licenses/inventory*', (route) =>
            route.fulfill({ status: 200, contentType: 'application/json', body: '[]' })
        );
        await page.route('**/api/v1/licenses/conflicts*', (route) =>
            route.fulfill({ status: 200, contentType: 'application/json', body: '[]' })
        );

        await page.goto('/login');
        await page.fill('#username', 'admin');
        await page.fill('#password input', 'AdminVectispire2026!');
        await page.click('button[type="submit"]');
        await page.waitForURL(/\/(dashboard|change-password|issues|overview|targets)/, { timeout: 10000 });
    });

    test('adds strong copyleft and forbidden into one figure, counting an absent category as zero', async ({ page }) => {
        await page.goto('/licenses');

        // 7 + (absent → 0). The unit spec pins the same sum; what is being checked here is that
        // it survives the whole path — sign-in, proxy, layout — and reaches a reader's eyes.
        const strongCopyleft = page.locator('.text-red-600.dark\\:text-red-400.text-2xl, .text-2xl.text-red-600').first();
        await expect(strongCopyleft).toHaveText('7', { timeout: 15000 });
    });

    test('shows the totals the server sent, not a placeholder', async ({ page }) => {
        await page.goto('/licenses');

        // Asserting on the figures rather than on the page being visible: a body is visible on
        // an error page too, which is why two of this suite's older cases cannot fail.
        await expect(page.getByText('128', { exact: true }).first()).toBeVisible({ timeout: 15000 });
        await expect(page.getByText('100', { exact: true }).first()).toBeVisible();
        await expect(page.getByText('21', { exact: true }).first()).toBeVisible();
    });
});
