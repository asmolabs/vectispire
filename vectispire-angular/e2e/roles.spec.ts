import { test, expect, type Page } from '@playwright/test';
import { goTo, signIn, signInAs, TRIAGE_BUTTON } from './support/session';
import { resetLoginThrottle, seedOneIssue } from './support/fixture';

/**
 * What each role sees, in a real browser.
 *
 * <p><b>Three screens and one flow shipped without any browser looking at them.</b> The unit specs
 * cover the components; the browser suite knew neither `/attestation`, nor `/forbidden`, nor the
 * auditor role — and a defect survived four days in there: the per-row triage button was not
 * guarded, while the bulk button was.
 *
 * <p>These cases talk to the real server without stubbing the API: what is tested here is the
 * agreement between what the route allows and what the screen offers. The triage suites do stub,
 * and that is what let them pass while the interface said something else.
 */
// **Serial.** The cases share account provisioning: run in parallel, two of them create the same
// account and the loser gets a refusal. They also share the sign-in attempt counter, which the
// server counts per address.
test.describe.configure({ mode: 'serial' });


/**
 * Waits until the list really has rows, and not merely a table on screen.
 *
 * <p><b>A visible table is not a loaded table.</b> The component renders with its header while the
 * request is in flight; `count()` does not retry, unlike `expect`, and therefore returned zero
 * buttons because there was not a row yet — a "the role does not see it" that spoke only of
 * latency.
 */
async function listed(page: Page): Promise<void> {
    await expect(page.getByRole('link', { name: 'CVE-2021-44228' })).toBeVisible({ timeout: 15_000 });
}

test.describe('what each role sees', () => {

    // The brute-force budget is global and narrow: without this, the case that receives the 429
    // is not the one that spent it. See `resetLoginThrottle`.
    test.beforeEach(() => resetLoginThrottle());

    // One vulnerability, without which the list is empty and "no triage button" is true for
    // everybody, guards included.
    test.beforeAll(() => seedOneIssue());

    test('an auditor reaches the attestation, and the audit chain is judged there', async ({ page }) => {
        await signInAs(page, 'AUDITOR');
        await goTo(page, '/attestation');

        // The chain first: it is the only claim on that page that demonstrates itself.
        await expect(page.getByText(/Audit chain (intact|broken)/)).toBeVisible({ timeout: 15000 });
        await expect(page).toHaveURL(/\/attestation/);
    });

    test('an auditor is offered no triage where a lead is offered one', async ({ page, browser }) => {
        // **The defect this case would have caught.** The per-row button was not guarded: it
        // showed, it opened the dialog, and saving collected a 403 — the broken screen the route
        // guards had just removed everywhere else.
        //
        // **Both roles are in the same case, deliberately.** An assertion of zero is only worth
        // something if the same selector, on the same screen, finds something for somebody. Split
        // apart, the positive control gets deleted one day without anything turning red, and what
        // is left is an assertion that passes because it looks for nothing.
        await signInAs(page, 'CISO');
        await goTo(page, '/issues');
        await listed(page);
        await expect(page.getByRole('button', { name: TRIAGE_BUTTON }),
            'triage must be offered to a security lead').not.toHaveCount(0);

        const other = await browser.newContext();
        try {
            const auditor = await other.newPage();
            await signInAs(auditor, 'AUDITOR');
            await goTo(auditor, '/issues');
            await listed(auditor);
            await expect(auditor.getByRole('button', { name: TRIAGE_BUTTON })).toHaveCount(0);
        } finally {
            await other.close();
        }
    });

    test('un compte ordinaire ne se voit offrir aucune porte qu\'on lui fermerait', async ({ page }) => {
        // **What this case learnt by failing.** It set out to check the refusal screen by having
        // an ordinary account click "Settings" — the link does not exist for them. The menu mirrors
        // the route guards one by one (`isSecurityLead` for the settings, `canReadGovernance` for
        // the posture, `isAdmin` for administration), so `/forbidden` is reachable by no click at
        // all: it is a net, and the net is empty because the floor holds. So it is the floor that
        // has to be tested.
        await signInAs(page, 'USER');

        // None of the guarded paths is offered to them. The selector aims at the `href` attribute
        // rather than at a label, so the check survives a translation.
        for (const path of ['/settings', '/users', '/teams', '/api-keys', '/agents',
                            '/ssh-keys', '/git-tokens', '/audit-log', '/gate-policies', '/rule-sets',
                            '/attestation']) {
            await expect(page.locator(`a[href="${path}"]`), `${path} must not be offered`)
                .toHaveCount(0);
        }

        // And a real product is left: the list of vulnerabilities opens for them.
        //
        // It is empty, and rightly so: `target_visibility` is `assigned`, the account is in no
        // team, and neither is the bootstrap repository. What this case asserts is that they reach
        // the screen — not a refusal, not the sign-in page — and not what they find there, which is
        // the subject of team scoping.
        await goTo(page, '/issues');
        await expect(page.locator('p-table').first()).toBeVisible({ timeout: 15_000 });
        await expect(page).toHaveURL(/\/issues/);
    });

    test('the remediation plan names an action, not a finding', async ({ page }) => {
        // **The calculation existed, the screen did not.** `/api/v1/remediation/high-impact-fixes`
        // ranked upgrades by leverage and `getHighImpactFixes` sat waiting in the front-end service
        // with no component calling it. This case is the first to cross the whole chain, from the
        // finding in the database to the sentence somebody reads on Monday morning.
        await signInAs(page, 'CISO');
        await goTo(page, '/remediation');

        // The seeded finding is a log4j-core 2.14.1 fixed in 2.17.1: the page must name the
        // package **and** the target version. Naming the package alone would be the list of
        // vulnerabilities under another title.
        await expect(page.getByText('log4j-core').first()).toBeVisible({ timeout: 15_000 });
        await expect(page.getByText('2.17.1').first()).toBeVisible();

        // Et jamais le texte de remplacement que le serveur renvoyait pour tout le monde.
        await expect(page.getByText('latest-patch')).toHaveCount(0);
    });

    test('the bootstrap account governs and does not act', async ({ page }) => {
        // The decision of 2 September, seen from the screen: SUPERUSER can lift the four-eyes rule,
        // so it cannot act under it. Without that separation, switching the control off and
        // settling alone stayed possible.
        await signIn(page);
        await goTo(page, '/issues');
        await listed(page);

        await expect(page.getByRole('button', { name: TRIAGE_BUTTON })).toHaveCount(0);
    });
});
