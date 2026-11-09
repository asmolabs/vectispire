import { test, expect, type Page } from '@playwright/test';
import { BOOTSTRAP_PASSWORD, E2E_PASSWORD, goTo, signInAs } from './support/session';
import { resetLoginThrottle } from './support/fixture';

/**
 * Solutions and projects (decision 0023), against the real server.
 *
 * <p>The unit spec pins the screen against fixtures; this pins it against the routes: that an
 * ordinary account reaches the tree through the sidebar and is offered no change, and that an
 * administrator's create, move, delete, the filing of an image and their confirmations go through. Names carry a suffix and are
 * deleted at the end, because the campaign's database survives a local re-run and names are
 * unique.
 */
test.describe.configure({ mode: 'serial' });

const NONE = { critical: 0, high: 0, medium: 0, low: 0, negligible: 0, unknown: 0, total: 0 };
const THREE_HIGH = { ...NONE, high: 3, total: 3 };

/**
 * One solution holding one project with three open high issues, at ids no seeded data uses. Its
 * languages are those of a counted repository beside one nobody has counted yet.
 */
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
                                checklistsVisible: true,
                                repositoryCount: 1,
                                openIssues: THREE_HIGH,
                                repositories: [
                                    { id: 987653, name: 'ledger-core' },
                                    { id: 987655, name: 'ledger-ui' }
                                ],
                                detectedLanguages: ['java', 'yaml'],
                                languagesUnknownFor: [987655]
                            }
                        ]
                    }
                ],
                unfiled: { repositoryCount: 0, openIssues: NONE, repositories: [] }
            })
        })
    );
}

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
     * The select is driven like a user would, because a move whose dialog opens but whose PATCH
     * never leaves is exactly what a component test cannot see.
     */
    test('an administrator moves a project to another solution', async ({ page }) => {
        const suffix = Date.now().toString(36);
        const from = `E2E from ${suffix}`;
        const to = `E2E to ${suffix}`;
        await signInAs(page, 'ADMIN');
        await goTo(page, '/solutions');

        for (const name of [from, to]) {
            await page.getByRole('button', { name: 'New solution' }).click();
            await page.locator('#node-name').fill(name);
            await page.getByRole('button', { name: 'Save' }).click();
            await expect(page.getByRole('heading', { name, level: 2 })).toBeVisible({ timeout: 15_000 });
        }
        const source = page.locator('section', { has: page.getByRole('heading', { name: from, level: 2 }) });
        const target = page.locator('section', { has: page.getByRole('heading', { name: to, level: 2 }) });

        await source.getByRole('button', { name: 'New project' }).click();
        await page.locator('#node-name').fill('Gateway');
        await page.getByRole('button', { name: 'Save' }).click();
        await expect(source.getByRole('heading', { name: 'Gateway', level: 3 })).toBeVisible({ timeout: 15_000 });

        await source.getByRole('button', { name: 'Move Gateway to another solution' }).click();
        await page.locator('p-select', { has: page.locator('#target-solution') }).click();
        await page.getByRole('option', { name: to, exact: true }).click();
        const patch = page.waitForRequest((request) => request.method() === 'PATCH');
        await page.locator('#move-project-confirm').getByRole('button').click();
        expect((await patch).postDataJSON()).toMatchObject({ solutionId: expect.any(Number) });

        await expect(page.getByTestId('notice')).toContainText(`Project Gateway moved to solution ${to}.`);
        await expect(target.getByRole('heading', { name: 'Gateway', level: 3 })).toBeVisible({ timeout: 15_000 });
        await expect(source.getByRole('heading', { name: 'Gateway', level: 3 })).toHaveCount(0);

        // The emptied solution can go; the one holding the project is cleaned up after it.
        await source.getByRole('button', { name: `Delete ${from}` }).click();
        await page.getByRole('button', { name: 'Confirm' }).click();
        await expect(page.getByRole('heading', { name: from, level: 2 })).toHaveCount(0, { timeout: 15_000 });
        await target.getByRole('button', { name: 'Delete Gateway' }).click();
        await page.getByRole('button', { name: 'Confirm' }).click();
        await expect(target.getByRole('heading', { name: 'Gateway', level: 3 })).toHaveCount(0, { timeout: 15_000 });
        await target.getByRole('button', { name: `Delete ${to}` }).click();
        await page.getByRole('button', { name: 'Confirm' }).click();
        await expect(page.getByRole('heading', { name: to, level: 2 })).toHaveCount(0, { timeout: 15_000 });
    });

    /**
     * An image filed into a project and taken out again, through the select and the confirmation a
     * user drives. The image and the project are created through the API — the screens that create
     * them have suites of their own — and the containers page is read in between, because the
     * project it shows comes from another route than the tree's.
     */
    test('an administrator files an image into a project, sees it on the image list, and removes it', async ({
        page
    }) => {
        const suffix = Date.now().toString(36);
        await signInAs(page, 'ADMIN');
        const headers = { Authorization: `Bearer ${await adminToken(page)}` };
        const solution = await page.request.post('/api/v1/solutions', {
            headers,
            data: { name: `E2E images ${suffix}` }
        });
        expect(solution.ok(), await solution.text()).toBe(true);
        const solutionId = ((await solution.json()) as { id: number }).id;
        const project = await page.request.post(`/api/v1/solutions/${solutionId}/projects`, {
            headers,
            data: { name: `Runtime ${suffix}` }
        });
        expect(project.ok(), await project.text()).toBe(true);
        const projectId = ((await project.json()) as { id: number }).id;
        const container = await page.request.post('/api/v1/containers', {
            headers,
            data: { image_name: `e2e/image-${suffix}`, tag: '1.0' }
        });
        expect(container.ok(), await container.text()).toBe(true);
        const containerId = ((await container.json()) as { id: number }).id;

        try {
            await goTo(page, '/solutions');
            const unfiled = page.getByTestId('unfiled');
            const row = unfiled.getByTestId('unfiled-image').filter({ hasText: `image-${suffix}` });
            await expect(row).toBeVisible({ timeout: 15_000 });
            const name = (await row.getByRole('link').innerText()).trim();

            await page.getByRole('button', { name: `File ${name} into a project` }).click();
            await page.locator('p-select', { has: page.locator('#target-project') }).click();
            await page.getByRole('option', { name: `Runtime ${suffix}`, exact: true }).click();
            await expect(page.getByTestId('file-consequence')).toContainText(
                `Filing ${name} into E2E images ${suffix} / Runtime ${suffix} is an access change`
            );
            const put = page.waitForRequest((request) => request.method() === 'PUT');
            await page.getByRole('dialog').getByRole('button', { name: 'File into project' }).click();
            expect(new URL((await put).url()).pathname).toBe(`/api/v1/projects/${projectId}/containers/${containerId}`);

            const filed = page.getByTestId(`project-${projectId}`);
            await expect(filed.getByTestId('project-image')).toContainText(name, { timeout: 15_000 });
            await expect(filed.getByTestId('container-count')).toContainText('Images: 1');
            await expect(row).toHaveCount(0);

            await goTo(page, '/containers');
            const link = page.getByRole('link', { name: `E2E images ${suffix} / Runtime ${suffix}` });
            await expect(link).toBeVisible({ timeout: 15_000 });
            await expect(link).toHaveAttribute('href', `/solutions#project-${projectId}`);

            await goTo(page, '/solutions');
            await filed.getByRole('button', { name: `Remove ${name} from its project` }).click();
            await expect(page.getByTestId('confirm-text')).toContainText(`Return ${name} to “no project”?`);
            await page.getByRole('button', { name: 'Confirm' }).click();
            await expect(filed.getByTestId('project-image')).toHaveCount(0, { timeout: 15_000 });
            await expect(row).toBeVisible();
        } finally {
            await page.request.delete(`/api/v1/containers/${containerId}`, { headers });
            await page.request.delete(`/api/v1/projects/${projectId}`, { headers });
            await page.request.delete(`/api/v1/solutions/${solutionId}`, { headers });
        }
    });

    /**
     * A plugin's languages beside the project's, in a real browser. The tree and the registry are
     * stubbed — a real count needs a completed scan, which this campaign's worker does not run.
     */
    test("the plugins dialog sets a plugin's languages against the project's", async ({ page }) => {
        await stubTree(page);
        const manifest = (id: string, languages: string[]) => ({
            id,
            name: id,
            image: `registry.example/${id}@sha256:${'a'.repeat(64)}`,
            languages,
            arguments: ['{source}'],
            output: 'results.sarif',
            exit_codes: [0],
            network: false,
            network_justification: null,
            timeout_seconds: 600,
            signature: null
        });
        const plugin = (id: string, languages: string[]) => ({
            id,
            name: id,
            manifest: manifest(id, languages),
            manifestDigest: 'b'.repeat(64),
            enabled: true,
            createdAt: '2026-09-27T08:00:00Z',
            createdBy: 'admin',
            updatedAt: null,
            updatedBy: null
        });
        await page.route('**/api/v1/plugins', (route) =>
            route.fulfill({
                status: 200,
                contentType: 'application/json',
                body: JSON.stringify([plugin('e2e-java-lint', ['java', 'kotlin']), plugin('e2e-py-rules', ['python'])])
            })
        );
        await page.route('**/api/v1/projects/987654/plugins', (route) =>
            route.fulfill({ status: 200, contentType: 'application/json', body: '[]' })
        );
        await signInAs(page, 'AUDITOR');
        await goTo(page, '/solutions');

        await page.getByRole('button', { name: 'Plugins switched on for Ledger' }).click();
        const dialog = page.getByTestId('plugins-dialog');
        await expect(dialog.getByTestId('plugins-project-languages')).toContainText('java');
        await expect(dialog.getByTestId('plugins-languages-unknown')).toContainText('(1): ledger-ui');
        await expect(page.getByTestId('project-plugin-e2e-java-lint')).toContainText('Present in this project: java.');
        await expect(page.getByTestId('project-plugin-e2e-py-rules')).toContainText(
            'those not yet scanned may hold one'
        );
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
