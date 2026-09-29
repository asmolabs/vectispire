import { test, expect } from '@playwright/test';
import type { components } from '../src/app/core/api.generated';
import { resetLoginThrottle } from './support/fixture';
import { goTo, signIn, signInAs } from './support/session';

type Manifest = components['schemas']['PluginManifest'];

/**
 * The plugin registry and the SARIF sources (decision 0017), against the real server.
 *
 * <p>The unit specs pin each screen against fixtures read from the contract; this pins the roles
 * against the routes: every account reaches the registry and is offered no change — through the
 * Administration section for the accounts that see it, through the route for the others — the
 * platform governor registers a plugin and sees the digest the server computed, and the
 * SARIF sources are in the sidebar for governance readers only — a link that leads to a refusal is
 * the defect the menu suite already watches for.
 *
 * <p><b>Ids carry a suffix and are never cleaned up</b>, because a plugin cannot be deleted: that is
 * the product's rule, not the suite's. The campaign's SQLite file is disposable.
 */
test.describe.configure({ mode: 'serial' });

test.describe('Plugins and SARIF sources', () => {
    test.beforeEach(() => resetLoginThrottle());

    test('an ordinary account reads the registry and is offered no change, nor the declared sources', async ({
        page
    }) => {
        await signInAs(page, 'USER');

        // **No menu link, and still the page.** The product owner made the entry an administration
        // one, knowing an ordinary account loses the link; the route stays open to it, as a scan's
        // link to an absent plugin needs. A `page.goto` would reload and drop the in-memory session,
        // so the router is driven the way a link inside the application drives it.
        await expect(page.locator('app-menu a[href="/plugins"]')).toHaveCount(0);
        await page.evaluate(() => {
            history.pushState(null, '', '/plugins');
            window.dispatchEvent(new PopStateEvent('popstate'));
        });
        await expect(page).toHaveURL(/\/plugins(\?|$)/, { timeout: 15_000 });

        await expect(page.getByRole('heading', { name: 'Plugins', level: 1 })).toBeVisible({ timeout: 15_000 });
        await expect(page.getByRole('button', { name: 'Register a plugin' })).toHaveCount(0);
        await expect(page.getByRole('link', { name: 'Declared sources' })).toHaveCount(0);
    });

    test('an auditor is offered the declared sources and cannot declare one', async ({ page }) => {
        await signInAs(page, 'AUDITOR');
        await goTo(page, '/sarif-sources');

        await expect(page.getByRole('heading', { name: 'Declared sources', level: 1 })).toBeVisible({ timeout: 15_000 });
        await expect(page.getByRole('button', { name: 'Declare a source' })).toHaveCount(0);
    });

    test('the platform governor registers a plugin through the form and reads back its digest', async ({ page }) => {
        const id = `e2e-${Date.now().toString(36)}`;
        // Typed from the generated contract: what the form sends must be a manifest the server reads.
        const manifest: Manifest = {
            id,
            name: 'E2E house rules',
            image: `registry.example.internal/sec/e2e-lint@sha256:${'a'.repeat(64)}`,
            languages: ['java'],
            arguments: ['{source}'],
            output: 'results.sarif',
            exit_codes: [0],
            network: false
        };

        await signIn(page);
        await goTo(page, '/plugins');

        await page.getByRole('button', { name: 'Register a plugin' }).click();
        await expect(page.getByTestId('id-permanent')).toContainText('can never be renamed');
        await page.locator('#plugin-id').fill(manifest.id!);
        await page.locator('#plugin-name').fill(manifest.name!);
        await page.locator('#plugin-image').fill(manifest.image!);
        // The multiselect's `inputId` lands on a hidden input; the component is what takes the click.
        await page.locator('p-multiselect', { has: page.locator('#plugin-languages') }).click();
        await page.getByRole('option', { name: 'java', exact: true }).click();
        await page.keyboard.press('Escape');

        const saved = page.waitForResponse(
            (response) => response.url().endsWith('/api/v1/plugins') && response.request().method() === 'POST'
        );
        await page.getByRole('dialog').getByRole('button', { name: 'Register a plugin' }).click();
        const response = await saved;
        expect(response.status()).toBe(201);
        const created = (await response.json()) as components['schemas']['PluginView'];
        expect(created.manifest?.image).toBe(manifest.image);

        await expect(page.getByTestId('manifest-digest')).toContainText(created.manifestDigest!, { timeout: 15_000 });
        await expect(page.getByTestId(`plugin-${id}`)).toContainText('Enabled');
    });
});
