import { test, expect, type Page } from '@playwright/test';
import { BOOTSTRAP_PASSWORD, E2E_PASSWORD, goTo, signInAs } from './support/session';
import { resetLoginThrottle } from './support/fixture';

/**
 * A project's page and a solution's compliance, against the real server.
 *
 * <p>The unit spec pins the drawing against fixtures; this pins it against the routes: that the tree
 * links to both, that a project holding one image nobody has scanned reads as unmeasured — a dash, "No
 * data" — with its component list flagged incomplete, that the CycloneDX export saves a file through
 * the client, and that an unknown project is the not-found state. Names carry a suffix and are
 * deleted at the end, because the campaign's SQLite file survives a local re-run.
 */
test.describe.configure({ mode: 'serial' });

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

test.describe('A project page', () => {
    test.beforeEach(() => resetLoginThrottle());

    test('opens from the tree, reads unmeasured, flags its list incomplete and exports CycloneDX', async ({ page }) => {
        const suffix = Date.now().toString(36);
        await signInAs(page, 'ADMIN');
        const headers = { Authorization: `Bearer ${await adminToken(page)}` };
        const solution = await page.request.post('/api/v1/solutions', {
            headers,
            data: { name: `E2E page ${suffix}` }
        });
        expect(solution.ok(), await solution.text()).toBe(true);
        const solutionId = ((await solution.json()) as { id: number }).id;
        const project = await page.request.post(`/api/v1/solutions/${solutionId}/projects`, {
            headers,
            data: { name: `Edge ${suffix}` }
        });
        expect(project.ok(), await project.text()).toBe(true);
        const projectId = ((await project.json()) as { id: number }).id;
        const container = await page.request.post('/api/v1/containers', {
            headers,
            data: { image_name: `e2e/edge-${suffix}`, tag: '1.0' }
        });
        expect(container.ok(), await container.text()).toBe(true);
        const containerId = ((await container.json()) as { id: number }).id;
        const filed = await page.request.put(`/api/v1/projects/${projectId}/containers/${containerId}`, { headers });
        expect(filed.ok(), await filed.text()).toBe(true);

        try {
            await goTo(page, '/solutions');
            await page.getByTestId(`project-${projectId}`).getByTestId('project-link').click();
            await expect(page).toHaveURL(new RegExp(`/projects/${projectId}$`));

            await expect(page.getByTestId('project-title')).toHaveText(`Edge ${suffix}`, { timeout: 15_000 });
            await expect(page.getByTestId('project-solution')).toHaveText(`In the solution E2E page ${suffix}`);
            await expect(page.getByTestId('project-issues')).toHaveAttribute(
                'href',
                `/issues?project_id=${projectId}&unsettled=true`
            );

            // Never scanned: every verdict is NO_DATA, and the score starting at a hundred is no score.
            await expect(page.getByTestId('scorecard-score')).toHaveText('—', { timeout: 15_000 });
            await expect(page.getByTestId('scorecard-grade')).toHaveText('No data');
            await expect(page.getByTestId('framework-NIS_2')).toContainText('No data');

            await expect(page.getByTestId('incomplete')).toContainText('Incomplete list: 1 target(s)');
            await expect(page.getByTestId(`inventory-container-${containerId}`)).toContainText('Never scanned');

            const download = page.waitForEvent('download');
            await page.locator('#download-cyclonedx button').click();
            const saved = await download;
            const body = JSON.parse(
                await new Promise<string>((resolve, reject) => {
                    void saved.createReadStream().then((stream) => {
                        let text = '';
                        stream.on('data', (chunk: Buffer) => (text += chunk.toString('utf8')));
                        stream.on('end', () => resolve(text));
                        stream.on('error', reject);
                    });
                })
            ) as { bomFormat?: string; specVersion?: string };
            expect(body.bomFormat).toBe('CycloneDX');
            expect(body.specVersion).toBe('1.5');

            await goTo(page, '/solutions');
            await page.getByTestId(`solution-${solutionId}`).getByTestId('solution-compliance').click();
            await expect(page.getByTestId('solution-title')).toHaveText(`Compliance and score — E2E page ${suffix}`, {
                timeout: 15_000
            });
            await expect(page.getByTestId('scorecard-score')).toHaveText('—');
        } finally {
            await page.request.delete(`/api/v1/containers/${containerId}`, { headers });
            await page.request.delete(`/api/v1/projects/${projectId}`, { headers });
            await page.request.delete(`/api/v1/solutions/${solutionId}`, { headers });
        }
    });

    test('an unknown project is the not-found state, not an error', async ({ page }) => {
        await signInAs(page, 'USER');
        await goTo(page, '/solutions');
        // Through the router, as a link would: a `page.goto` reloads and drops the in-memory session.
        await page.evaluate(() => {
            history.pushState(null, '', '/projects/987000123');
            window.dispatchEvent(new PopStateEvent('popstate'));
        });
        await expect(page.getByTestId('not-found')).toHaveText(
            'This project does not exist, or you see none of its repositories and images.',
            { timeout: 15_000 }
        );
        await expect(page.getByTestId('error')).toHaveCount(0);
    });
});
