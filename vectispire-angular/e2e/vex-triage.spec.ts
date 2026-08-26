import { test, expect } from '@playwright/test';
import { goTo, signIn } from './support/session';

/**
 * The vulnerability backlog and the VEX statement a triage decision produces.
 *
 * **Both cases in this file used to assert `expect(body).toBeVisible()`** — which passes on an
 * error page, on a blank page, and on a redirect back to sign-in. They counted towards the browser
 * suite and verified nothing. Replaced with assertions that read what the page actually did.
 *
 * The backlog is stubbed rather than seeded: what is under test is the screen, and a fixture that
 * depended on what a scan happened to find would make a rendering failure look like empty data.
 * Authentication is *not* stubbed — signing in for real is half of what a browser case is for.
 */
test.describe('VEX Triage & Backlog Management E2E', () => {

    const ISSUE = {
        id: 4242,
        repoId: 7,
        containerId: null,
        targetKind: 'repository',
        targetName: 'ours',
        type: 'vulnerability',
        identifier: 'CVE-2021-44228',
        severity: 'critical',
        packageName: 'log4j-core',
        packageVersion: '2.14.1',
        purl: 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1',
        filePath: 'pom.xml',
        line: null,
        cvssScore: 10.0,
        epssScore: 0.97,
        isKev: true,
        fixState: 'fixed',
        fixVersions: '2.17.1',
        link: null,
        description: null,
        state: 'open',
        firstSeenAt: '2026-08-01T00:00:00Z',
        lastSeenAt: '2026-08-26T00:00:00Z',
        timesSeen: 3,
        triageStatus: 'under_review',
        triageJustification: null,
        triageComment: null,
        triagedBy: null,
        triagedAt: null,
        triageExpiresAt: null,
        isDirectDependency: true,
        ticketRef: null,
        ticketUrl: null,
        slaDueAt: null
    };

    async function stubBacklog(page: import('@playwright/test').Page): Promise<void> {
        await page.route('**/api/v1/issues?**', (route) =>
            route.fulfill({
                status: 200,
                contentType: 'application/json',
                body: JSON.stringify({ items: [ISSUE], total: 1, offset: 0, limit: 25 })
            })
        );
    }

    test.beforeEach(async ({ page }) => {
        await signIn(page);
    });

    test('the backlog renders the finding the server returned', async ({ page }) => {
        await stubBacklog(page);
        await goTo(page, '/issues');

        // Each of these fails on an error page, on an empty table, and on a redirect to sign-in —
        // which is precisely what the assertion this replaced could not tell apart.
        await expect(page.getByText('CVE-2021-44228').first()).toBeVisible({ timeout: 15000 });
        await expect(page.getByText('log4j-core').first()).toBeVisible();
        await expect(page.getByRole('button', { name: 'Triage' }).first()).toBeVisible();
    });

    test('a triage decision is sent as a VEX statement carrying its status', async ({ page }) => {
        await stubBacklog(page);

        let submitted: Record<string, unknown> | null = null;
        await page.route('**/api/v1/issues/4242/triage', async (route) => {
            submitted = route.request().postDataJSON();
            await route.fulfill({
                status: 200,
                contentType: 'application/json',
                body: JSON.stringify({ ...ISSUE, triageStatus: 'under_review', triagedBy: 'admin' })
            });
        });

        await goTo(page, '/issues');
        await page.getByRole('button', { name: 'Triage' }).first().click();

        const dialog = page.getByRole('dialog');
        await expect(dialog).toBeVisible({ timeout: 15000 });
        await dialog.getByRole('button', { name: /save|enregistrer/i }).click();

        // The point of the case: a decision leaves as a statement, addressed to this issue and
        // carrying the status the dialog held. A page that posted an empty body, or posted to the
        // wrong id, would still have closed its dialog and looked correct.
        await expect.poll(() => submitted, { timeout: 15000 }).not.toBeNull();
        expect(submitted).toMatchObject({ status: 'under_review' });
        await expect(dialog).toBeHidden();
    });
});
