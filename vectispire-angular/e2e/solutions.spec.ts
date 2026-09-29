import { test, expect, type Page } from '@playwright/test';
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

const NONE = { critical: 0, high: 0, medium: 0, low: 0, negligible: 0, unknown: 0, total: 0 };
const THREE_HIGH = { ...NONE, high: 3, total: 3 };

/** One solution holding one project with three open high issues, at ids no seeded data uses. */
async function stubTree(page: Page): Promise<void> {
    await page.route('**/api/v1/solutions', (route) =>
        route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
                solutions: [
                    {
                        id: 987650,
                        name: 'E2E Payments',
                        description: null,
                        createdAt: '2026-09-01T00:00:00Z',
                        partial: false,
                        repositoryCount: 1,
                        openIssues: THREE_HIGH,
                        projects: [
                            {
                                id: 987654,
                                solutionId: 987650,
                                name: 'Ledger',
                                description: null,
                                createdAt: '2026-09-01T00:00:00Z',
                                partial: false,
                                repositoryCount: 1,
                                openIssues: THREE_HIGH,
                                repositories: [{ id: 987653, name: 'ledger-core' }]
                            }
                        ]
                    }
                ],
                unfiled: { repositoryCount: 0, openIssues: NONE, repositories: [] }
            })
        })
    );
}

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

    /**
     * A badge opens the list it counts. The tree is stubbed — a real one would need a scanned
     * repository filed in a project — and the backlog is the real server's: the project id exists
     * nowhere, so it also shows that an unknown project answers the ordinary empty list.
     */
    test('a severity badge on a project opens the backlog narrowed to it, unsettled only', async ({ page }) => {
        await stubTree(page);
        await signInAs(page, 'USER');
        await goTo(page, '/solutions');

        const badge = page.getByRole('link', { name: 'Open the issues of high severity in E2E Payments / Ledger (3)' });
        await expect(badge).toBeVisible({ timeout: 15_000 });
        const backlog = page.waitForRequest((request) => new URL(request.url()).pathname === '/api/v1/issues');
        await badge.click();

        const params = new URL((await backlog).url()).searchParams;
        expect(params.get('project_id')).toBe('987654');
        expect(params.get('severity')).toBe('high');
        expect(params.get('unsettled')).toBe('true');

        await expect(page).toHaveURL(/\/issues\?.*project_id=987654/);
        await expect(page.getByTestId('scope-project')).toContainText('Project: E2E Payments / Ledger');
        await expect(page.locator('#filter-unsettled')).toBeChecked();
        await expect(page.getByText('No issue matches these filters.')).toBeVisible();

        // Taking the chip off leaves the severity and the clause the badge set.
        await page.getByRole('button', { name: 'Remove the project filter E2E Payments / Ledger' }).click();
        await expect(page.getByTestId('scope-project')).toHaveCount(0);
        await expect(page).not.toHaveURL(/project_id/);
        await expect(page).toHaveURL(/severity=high/);
    });
});
