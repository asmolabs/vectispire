import { resetLoginThrottle } from './support/fixture';
import { test, expect } from '@playwright/test';
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

    /** The four entries of the evidence section reserved to governance read access. */
    const GOVERNANCE_ONLY = [
        'Compliance progression', 'Statement of applicability', 'Certified scope',
        'Verdict register', 'Audit log'
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
});
