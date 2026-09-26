import { test, expect } from '@playwright/test';
import { goTo, signInAs } from './support/session';
import { resetLoginThrottle } from './support/fixture';

/**
 * Solutions and projects (decision 0023), against the real server.
 *
 * <p>The unit spec pins the screen against fixtures; this pins it against the routes: that an
 * ordinary account reaches the tree through the sidebar and is offered no change, and that an
 * administrator's create, delete and their confirmations go through. Names carry a suffix and are
 * deleted at the end, because the campaign's SQLite file survives a local re-run and names are
 * unique.
 */
test.describe.configure({ mode: 'serial' });

test.describe('Solutions and projects', () => {
    test.beforeEach(() => resetLoginThrottle());

    test('an ordinary account reads the tree and is offered no change', async ({ page }) => {
        await signInAs(page, 'USER');
        await goTo(page, '/solutions');

        // "No project" is always there, empty or not: it is how a reader knows the tree answered.
        await expect(page.getByRole('heading', { name: 'No project' })).toBeVisible({ timeout: 15_000 });
        await expect(page.getByRole('button', { name: 'New solution' })).toHaveCount(0);
    });

    test('an administrator creates a solution and a project, and deletes both', async ({ page }) => {
        const name = `E2E ${Date.now().toString(36)}`;
        await signInAs(page, 'ADMIN');
        await goTo(page, '/solutions');

        await page.getByRole('button', { name: 'New solution' }).click();
        await page.locator('#node-name').fill(name);
        await page.getByRole('button', { name: 'Save' }).click();

        const solution = page.locator('section', { has: page.getByRole('heading', { name, level: 2 }) });
        await expect(solution).toBeVisible({ timeout: 15_000 });

        await solution.getByRole('button', { name: 'New project' }).click();
        await page.locator('#node-name').fill('Gateway');
        await page.getByRole('button', { name: 'Save' }).click();
        await expect(solution.getByRole('heading', { name: 'Gateway', level: 3 })).toBeVisible({ timeout: 15_000 });

        // The confirmation says what a project deletion takes away, before it is confirmed.
        await solution.getByRole('button', { name: 'Delete Gateway' }).click();
        await expect(page.getByTestId('confirm-text')).toContainText('every grant naming this project is revoked');
        await page.getByRole('button', { name: 'Confirm' }).click();
        await expect(solution.getByRole('heading', { name: 'Gateway', level: 3 })).toHaveCount(0, { timeout: 15_000 });

        await solution.getByRole('button', { name: `Delete ${name}` }).click();
        await page.getByRole('button', { name: 'Confirm' }).click();
        await expect(page.getByRole('heading', { name, level: 2 })).toHaveCount(0, { timeout: 15_000 });
    });
});
