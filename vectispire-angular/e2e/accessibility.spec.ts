import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';
import { resetLoginThrottle } from './support/fixture';
import { signIn } from './support/session';

/**
 * WCAG 2.2 AA, as far as a machine can tell, on every screen of the sidebar and in both themes.
 *
 * <p><b>Only the rules tagged with a WCAG success criterion</b>, levels A and AA of 2.0 to 2.2: axe's
 * best practices are advice, and a check that fails on advice gets switched off. What axe cannot see —
 * focus order, a dialog returning focus, a live region announcing at the right moment — is not covered
 * here; the unit specs and the review are where those are held.
 *
 * <p><b>Both themes, because contrast is a property of the palette.</b> Dark mode had never been looked
 * at by anything but a person, and a token light enough on white is often too dark on the dark surface.
 */
const WCAG_AA = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'];

/**
 * The screens, by route. Reached through the router rather than `page.goto`, which would drop the
 * session held in memory (see `goTo`); the sidebar's nested groups would make a click per screen
 * depend on which group happens to be open.
 */
const SCREENS = [
    '/dashboard',
    '/security',
    '/issues',
    '/remediation',
    '/remediation-delays',
    '/history',
    '/inventory',
    '/epss',
    '/blast-radius',
    '/licenses',
    '/attack-surface',
    '/attack-paths',
    '/owasp',
    '/compliance',
    '/exceptions',
    '/compliance-history',
    '/soa',
    '/certified-scope',
    '/gate-verdicts',
    '/attestation',
    '/repositories',
    '/solutions',
    '/containers',
    '/notifications',
    '/ssh-keys',
    '/git-tokens',
    '/gate-policies',
    '/rule-sets',
    '/sarif-sources',
    '/plugins',
    '/integrations',
    '/report-plugins',
    '/checklist-templates',
    '/audit-log',
    '/api-keys',
    '/agents',
    '/forge-connections',
    '/users',
    '/teams',
    '/settings',
    '/account'
];

async function navigate(page: Page, path: string): Promise<void> {
    // The router listens to `popstate`: this is an in-application navigation, the session kept.
    await page.evaluate((target) => {
        history.pushState({}, '', target);
        dispatchEvent(new PopStateEvent('popstate', { state: {} }));
    }, path);
    await expect(page).toHaveURL(new RegExp(`${path}(\\?|$)`));
    // Settled: a screen's first answers drawn, so what is checked is the screen and not its spinner.
    await page.waitForLoadState('networkidle');
    await expect(page.locator('p-progressspinner, .p-skeleton')).toHaveCount(0, { timeout: 15_000 });
}

async function violationsOn(page: Page, path: string): Promise<string[]> {
    await navigate(page, path);
    const { violations } = await new AxeBuilder({ page })
        .withTags(WCAG_AA)
        // Inactive controls are exempt from contrast (1.4.3); a button busy with its request is one.
        .exclude('.p-disabled')
        .exclude('.p-button-loading')
        .analyze();
    return violations.flatMap((violation) =>
        violation.nodes.map(
            (node) =>
                `${path} — ${violation.id} (${violation.impact}): ${node.target.join(' ')} — ${node.failureSummary}`
        )
    );
}

test.describe('accessibility', () => {
    test.beforeEach(() => resetLoginThrottle());
    test.beforeEach(async ({ page }) => {
        await signIn(page);
    });

    // One case per theme, every screen inside it: a sign-in per screen would cost the brute-force
    // budget forty-one times for nothing.
    for (const theme of ['light', 'dark'] as const) {
        test(`every screen meets WCAG 2.2 AA in the ${theme} theme`, async ({ page }) => {
            test.setTimeout(600_000);
            if (theme === 'dark') {
                await page.getByRole('button', { name: /dark theme|thème sombre/i }).click();
                await expect(page.locator('html')).toHaveClass(/app-dark/);
            }
            // Colours read mid fade-in are half of what the reader ends up seeing: axe measures what is
            // drawn, so the transitions are cut short rather than waited for.
            await page.addStyleTag({
                content: '*, *::before, *::after { transition: none !important; animation: none !important; }'
            });
            const found: string[] = [];
            for (const path of SCREENS) {
                found.push(...(await violationsOn(page, path)));
            }
            expect(found, found.join('\n')).toEqual([]);
        });
    }

    // Axe cannot see where focus goes. Optimus traps it inside a dialog and dropped it on `<body>` when
    // the dialog closed; `DialogFocusReturn` gives it back, and only a real browser removes the dialog
    // the way Optimus does.
    test('a dialog keeps focus inside, and gives it back to its opener when it closes', async ({ page }) => {
        await navigate(page, '/teams');
        const create = page.getByRole('button', { name: 'Create Team' });
        await create.focus();
        await page.keyboard.press('Enter');
        const dialog = page.getByRole('dialog');
        await expect(dialog).toBeVisible();
        const focusInside = () => dialog.evaluate((element) => element.contains(document.activeElement));
        await expect.poll(focusInside).toBe(true);
        for (let i = 0; i < 8; i++) {
            await page.keyboard.press('Tab');
            expect(await focusInside()).toBe(true);
        }
        await page.keyboard.press('Escape');
        await expect(dialog).toHaveCount(0);
        await expect(create).toBeFocused();
    });
});
