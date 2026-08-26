import { test, expect, type Page } from '@playwright/test';
import { goTo, signIn } from './support/session';

/**
 * The four-eyes workflow, seen from the screen an operator uses.
 *
 * **What this covers and what it does not, stated rather than implied.** The rule itself — that a
 * request to exempt enters `pending_approval` and only a second pair of eyes can settle it — lives
 * on the server and is covered there by `TriageTest`, `IssueTriageServiceTest` and
 * `BulkTriageRoutesTest`. Repeating that here would be a slower copy of a test that already
 * exists.
 *
 * <p>What only a browser can say is whether the screen lets an operator do it: whether the VEX
 * justification is genuinely required before a decision can be saved, whether the statement that
 * leaves carries the status and the justification, and whether a pending decision reads as pending
 * rather than as settled. Those three are here.
 *
 * <p>Both cases in this file previously asserted `expect(body).toBeVisible()`, which is true on
 * the sign-in screen — where, before the session helper existed, they were in fact looking.
 */
test.describe('Double Validation (Four-Eyes Approval) Workflow E2E', () => {

    const OPEN_ISSUE = issue({ triageStatus: 'under_review', triageJustification: null });
    const PENDING_ISSUE = issue({
        triageStatus: 'pending_approval',
        triageJustification: 'vulnerable_code_not_in_execute_path',
        triagedBy: 'reader'
    });

    function issue(overrides: Record<string, unknown>) {
        return {
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
            purl: null,
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
            slaDueAt: null,
            ...overrides
        };
    }

    async function stubBacklog(page: Page, row: unknown): Promise<void> {
        await page.route('**/api/v1/issues?**', (route) =>
            route.fulfill({
                status: 200,
                contentType: 'application/json',
                body: JSON.stringify({ items: [row], total: 1, offset: 0, limit: 25 })
            })
        );
    }

    /** Picks an option out of a PrimeNG overlay, which is appended to the body rather than inline. */
    async function choose(page: Page, label: string): Promise<void> {
        await page.getByRole('option', { name: label, exact: true }).click();
    }

    test.beforeEach(async ({ page }) => {
        await signIn(page);
    });

    test('an exemption cannot be saved without the justification the VEX standard requires', async ({ page }) => {
        await stubBacklog(page, OPEN_ISSUE);
        await goTo(page, '/issues');

        await page.getByRole('button', { name: 'Triage' }).first().click();
        const dialog = page.getByRole('dialog');
        await expect(dialog).toBeVisible({ timeout: 15000 });

        const save = dialog.getByRole('button', { name: /save|enregistrer/i });
        // `under_review` needs nothing, so the button starts usable — the point is what happens
        // when the decision becomes one that has to be justified.
        await expect(save).toBeEnabled();

        await dialog.locator('p-select').first().click();
        await choose(page, 'Not affected');

        // **The rule, on screen.** Without a justification an exported VEX statement would say
        // "not affected" and give no reason, which is a claim nobody can check. The screen refuses
        // to send it rather than sending it and letting the server explain.
        await expect(save).toBeDisabled();
    });

    test('a justified exemption leaves as a statement, and comes back pending a second pair of eyes', async ({ page }) => {
        await stubBacklog(page, OPEN_ISSUE);

        let submitted: Record<string, unknown> | null = null;
        await page.route('**/api/v1/issues/4242/triage', async (route) => {
            submitted = route.request().postDataJSON();
            // What the server answers when four-eyes is on: the decision is recorded, not applied.
            await route.fulfill({
                status: 200,
                contentType: 'application/json',
                body: JSON.stringify(PENDING_ISSUE)
            });
        });

        await goTo(page, '/issues');
        await page.getByRole('button', { name: 'Triage' }).first().click();
        const dialog = page.getByRole('dialog');
        await expect(dialog).toBeVisible({ timeout: 15000 });

        await dialog.locator('p-select').first().click();
        await choose(page, 'Not affected');
        await dialog.locator('p-select').nth(1).click();
        await choose(page, 'Vulnerable code not in the execute path');

        await dialog.getByRole('button', { name: /save|enregistrer/i }).click();

        await expect.poll(() => submitted, { timeout: 15000 }).not.toBeNull();
        expect(submitted).toMatchObject({
            status: 'not_affected',
            justification: 'vulnerable_code_not_in_execute_path'
        });

        // **And it must not read as settled.** The row now says "Pending approval": an exemption
        // shown as "Not affected" before anyone approved it is the whole failure mode four-eyes
        // exists to prevent, and it would look like success.
        await stubBacklog(page, PENDING_ISSUE);
        await expect(page.getByText('Pending approval').first()).toBeVisible({ timeout: 15000 });
    });
});
