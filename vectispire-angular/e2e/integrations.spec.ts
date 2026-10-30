import { test, expect, type Page } from '@playwright/test';
import type { components } from '../src/app/core/api.generated';
import { resetLoginThrottle } from './support/fixture';
import { BOOTSTRAP_PASSWORD, E2E_PASSWORD, goTo, signIn, signInAs } from './support/session';

type IntegrationView = components['schemas']['IntegrationView'];

/**
 * *Administration → Integrations* (decision 0040), against the real server.
 *
 * <p>The unit specs pin the screen against fixtures; this pins the switch against the route and what it
 * changes: the platform governor switches a forge off through the confirmation, the server records it, the
 * forge connections form stops offering it, and switching it back on offers it again. Every wait is on
 * what the server's answer changes — the response, then the row's state — never on a delay.
 *
 * <p><b>`forge.github` is switched back on whatever happens</b>, in an `afterEach` through the API: a run
 * that failed halfway would otherwise leave the campaign's database with a forge off, and every later suite
 * creating a GitHub connection would meet a 409 it did not cause.
 */
test.describe.configure({ mode: 'serial' });

const FORGE = 'forge.github';

/** A bearer token for `page.request`: the session lives in memory, where no request can read it. */
async function adminToken(page: Page): Promise<string> {
    for (const password of [E2E_PASSWORD, BOOTSTRAP_PASSWORD]) {
        const response = await page.request.post('/api/v1/auth/login', { data: { username: 'admin', password } });
        if (response.ok()) {
            const token = ((await response.json()) as { token?: string }).token;
            if (token) return token;
        }
    }
    throw new Error('no token for admin');
}

async function readBack(page: Page, key: string): Promise<IntegrationView> {
    const response = await page.request.get('/api/v1/integrations', {
        headers: { Authorization: `Bearer ${await adminToken(page)}` }
    });
    expect(response.ok(), await response.text()).toBe(true);
    const entry = ((await response.json()) as IntegrationView[]).find((one) => one.key === key);
    expect(entry, `the registry lists ${key}`).toBeDefined();
    return entry!;
}

function switched(page: Page, key: string) {
    return page.waitForResponse(
        (response) =>
            response.url().endsWith(`/api/v1/integrations/${key}/enabled`) && response.request().method() === 'PUT'
    );
}

test.describe('Integrations', () => {
    test.beforeEach(() => resetLoginThrottle());

    test.afterEach(async ({ page }) => {
        await page.request.put(`/api/v1/integrations/${FORGE}/enabled`, {
            headers: { Authorization: `Bearer ${await adminToken(page)}` },
            data: { enabled: true }
        });
    });

    test('the platform governor switches a forge off and on, and the connection form follows', async ({ page }) => {
        await signIn(page);
        await goTo(page, '/integrations');
        await expect(page.getByRole('heading', { name: 'Integrations', level: 1 })).toBeVisible({ timeout: 15_000 });

        const row = page.getByTestId(`integration-${FORGE}`);
        await expect(row.getByTestId('integration-state')).toHaveText('Enabled');

        // Off asks first, and says what is suspended and that nothing is deleted.
        await row.getByRole('button', { name: 'Switch off GitHub' }).click();
        const dialog = page.getByRole('dialog');
        await expect(dialog.getByTestId('confirm-suspends')).toContainText('connections to this forge are suspended');
        await expect(dialog.getByTestId('confirm-kept')).toContainText('Nothing is deleted');
        const off = switched(page, FORGE);
        await dialog.getByRole('button', { name: 'Switch off', exact: true }).click();
        expect((await off).status()).toBe(200);
        await expect(row.getByTestId('integration-state')).toHaveText('Disabled');
        await expect(row.getByTestId('integration-changed')).toContainText('by admin');

        const recorded = await readBack(page, FORGE);
        expect(recorded.enabled).toBe(false);
        expect(recorded.updatedBy).toBe('admin');

        // The form no longer offers it for a new connection.
        await goTo(page, '/forge-connections');
        await page.getByTestId('add-connection').click();
        await expect(page.locator('#forge-kind option')).toHaveText(['GitLab']);
        await page.getByRole('dialog').getByRole('button', { name: 'Cancel' }).click();
        await expect(page.getByRole('dialog')).toHaveCount(0);

        // On does not ask: it only resumes.
        await goTo(page, '/integrations');
        const on = switched(page, FORGE);
        await page.getByTestId(`integration-${FORGE}`).getByRole('button', { name: 'Switch on GitHub' }).click();
        expect((await on).status()).toBe(200);
        await expect(page.getByTestId(`integration-${FORGE}`).getByTestId('integration-state')).toHaveText('Enabled');
        expect((await readBack(page, FORGE)).enabled).toBe(true);

        await goTo(page, '/forge-connections');
        await page.getByTestId('add-connection').click();
        await expect(page.locator('#forge-kind option')).toHaveText(['GitLab', 'GitHub']);
    });

    test('an auditor reads the states and is offered no switch', async ({ page }) => {
        await signInAs(page, 'AUDITOR');
        await goTo(page, '/integrations');

        await expect(page.getByTestId(`integration-${FORGE}`).getByTestId('integration-state')).toHaveText('Enabled');
        await expect(page.getByTestId('integrations-rule')).toContainText('Only the platform governor');
        await expect(page.getByRole('button', { name: /^Switch (off|on) / })).toHaveCount(0);
    });
});
