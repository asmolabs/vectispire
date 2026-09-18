import { resetLoginThrottle } from './support/fixture';
import { test, expect, Page } from '@playwright/test';
import { goTo, signIn } from './support/session';

/**
 * The remediation plan, and the admission it has to make.
 *
 * <h2>The defect this case closes</h2>
 *
 * <p><b>A repository showed a single action against hundreds of open findings, and it was read as
 * a breakage.</b> The calculation was right: the ranking keeps only vulnerabilities carrying a
 * package name, because a line of the plan is a version bump, and that repository's backlog was
 * made of exposed secrets — which you revoke, not upgrade. Nothing on screen said so.
 *
 * <p>A wrong number gets corrected, mistrust is kept. What this case checks is therefore not a
 * number but <b>the agreement between a loaded response and what a reader understands of it</b>:
 * that the disproportion is named, and named by the move that actually closes the family.
 *
 * <p>The API is stubbed: what is tested is that agreement, not what a scan found.
 */
test.describe('Remediation plan', () => {

    test.beforeEach(() => resetLoginThrottle());

    async function stub(page: Page, pattern: string, body: unknown): Promise<void> {
        await page.route(pattern, (route) =>
            route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) }));
    }

    async function stubPlan(page: Page, coverage: unknown): Promise<void> {
        await stub(page, '**/api/v1/remediation/high-impact-fixes*', [{
            packageName: 'log4j-core',
            currentVersion: '2.14.1',
            recommendedVersion: '2.17.1',
            cveCountResolved: 12,
            criticalCveCount: 4,
            highCveCount: 8,
            estimatedHours: 1.3,
            leverageScore: 9.2,
            affectedCves: ['CVE-2021-44228'],
            affectedTargetNames: ['common-libs']
        }]);
        await stub(page, '**/api/v1/remediation/debt*', {
            totalOpenIssues: 412, criticalIssues: 4, highIssues: 8, mediumIssues: 0, lowIssues: 400,
            totalEstimatedHours: 812.3, totalEstimatedPersonDays: 101.5,
            vulnerabilitiesDebtHours: 12.3, secretsDebtHours: 798, sastDebtHours: 0,
            iacDebtHours: 2, licenseDebtHours: 0, eolDebtHours: 0, topHighImpactFixes: []
        });
        await stub(page, '**/api/v1/remediation/coverage*', coverage);
    }

    test('names what an upgrade cannot close, next to a plan of one line', async ({ page }) => {
        await stubPlan(page, {
            openFindings: 412,
            addressableByUpgrade: 12,
            beyondUpgrades: 400,
            gaps: [{ family: 'secret', findings: 399 }, { family: 'unpackaged', findings: 1 }]
        });
        await signIn(page);
        await goTo(page, '/remediation');

        await expect(page.getByText('What this plan cannot close')).toBeVisible({ timeout: 15000 });

        // The sentence, and not only the numbers: "12 of 412" is what makes the difference between
        // "one action" and "one action covering twelve findings, the other four hundred are
        // elsewhere".
        await expect(page.getByText('12 of the 412 open findings')).toBeVisible();

        // Et le geste, qui est le fond de l'affaire : on ne monte pas un secret de version.
        await expect(page.getByText('revoke and rotate', { exact: false })).toBeVisible();
    });

    test('says nothing when every finding closes with an upgrade', async ({ page }) => {
        // A warning shown when all is well loses its meaning within days, and then the one that
        // matters becomes invisible too.
        await stubPlan(page, {
            openFindings: 12, addressableByUpgrade: 12, beyondUpgrades: 0, gaps: []
        });
        await signIn(page);
        await goTo(page, '/remediation');

        await expect(page.getByText('log4j-core')).toBeVisible({ timeout: 15000 });
        await expect(page.getByText('What this plan cannot close')).toHaveCount(0);
    });
});
