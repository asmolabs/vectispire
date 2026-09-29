import { resetLoginThrottle } from './support/fixture';
import { test, expect, type Page } from '@playwright/test';
import { signInAs } from './support/session';

/**
 * The sidebar offers no link that leads to a refusal.
 *
 * <p><b>This product has had that defect before</b>, on the deployment keys: the route reserved
 * them to an administrator, the menu offered them to everybody, and that was the only way to reach
 * `/forbidden` by clicking. Grouping the evidence screens puts four governance-only routes into a
 * section everybody sees, so the same mistake becomes possible again — hence this case.
 *
 * <p>The assertion runs both ways: an ordinary account does not see them, and an auditor does. The
 * first half alone would pass on a menu that offers them to nobody.
 */
test.describe('Sidebar grouping', () => {

    test.beforeEach(() => resetLoginThrottle());

    /** Four of the evidence section's entries reserved to governance read access. */
    const GOVERNANCE_ONLY = [
        'Compliance progression', 'Statement of applicability', 'Certified scope',
        'Verdict register'
    ];

    /** Les trois que tout compte peut ouvrir. */
    const EVERYONE = ['Compliance matrix', 'OWASP report', 'Exceptions register'];

    test('offers an ordinary account no link it would be refused', async ({ page }) => {
        await signInAs(page, 'USER');

        for (const label of EVERYONE) {
            await expect(page.getByRole('link', { name: label }), label).toHaveCount(1);
        }
        for (const label of GOVERNANCE_ONLY) {
            await expect(page.getByRole('link', { name: label }), label).toHaveCount(0);
        }
    });

    test('offers an auditor the whole evidence section', async ({ page }) => {
        // Without this half, a menu offering these screens to nobody would pass the case above —
        // and that is exactly the shape of the defect this file watches for.
        await signInAs(page, 'AUDITOR');

        for (const label of [...EVERYONE, ...GOVERNANCE_ONLY]) {
            await expect(page.getByRole('link', { name: label }), label).toHaveCount(1);
        }
    });

    /** The links under one section title of the sidebar. */
    function section(page: Page, title: string) {
        return page.locator('app-menu li.layout-root-menuitem', {
            has: page.locator('.layout-menuitem-root-text', { hasText: title })
        });
    }

    test('files the plugins and the audit log under Administration, and offers them to no one else', async ({
        page, browser
    }) => {
        // The product owner's decision: both are administration entries. The audit log keeps the
        // governance-read condition it had among the evidence; the plugins go to whoever sees the
        // section, and an ordinary account loses the link while keeping the page.
        await signInAs(page, 'AUDITOR');
        for (const path of ['/plugins', '/audit-log']) {
            await expect(section(page, 'Administration').locator(`a[href="${path}"]`), path).toHaveCount(1);
            await expect(page.locator(`app-menu a[href="${path}"]`), `${path} only once`).toHaveCount(1);
        }

        const other = await browser.newContext();
        try {
            const user = await other.newPage();
            await signInAs(user, 'USER');
            for (const path of ['/plugins', '/audit-log']) {
                await expect(user.locator(`app-menu a[href="${path}"]`), path).toHaveCount(0);
            }
        } finally {
            await other.close();
        }
    });
});
