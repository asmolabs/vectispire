import { expect, test, type Page } from '@playwright/test';

/**
 * The documentation's screenshots, produced rather than taken.
 *
 * <h2>Why this exists at all</h2>
 *
 * <p><b>A screenshot captured by hand is a claim nobody confronts with reality.</b> The rest of
 * `docs-site` survived five contract changes in one day because it describes what a view answers
 * rather than what a cell says; an image is coupled to the pixel, and `mkdocs --strict` can see a
 * dead link but never a picture of a column removed three months ago.
 *
 * <p>Generating them puts that back under a check. Every capture below <b>navigates by clicking
 * the sidebar</b> and <b>asserts something specific before it shoots</b>, so a renamed route, a
 * missing menu entry or a screen that renders empty fails the run instead of producing a
 * confident-looking picture of nothing.
 *
 * <h2>Three things that make the output stable</h2>
 *
 * <p><b>The API is stubbed, including the sign-in.</b> No control plane, no database, nothing from
 * a real estate — so a screenshot cannot leak a repository URL, a CVE somebody is still fixing or
 * an account name, and the same run produces the same page on any machine.
 *
 * <p><b>The clock is frozen.</b> Screens show dates and relative ages; without this, every run
 * would produce a different image and the repository would fill with binary diffs that mean
 * nothing.
 *
 * <p><b>The assertions never read a label.</b> This file runs twice, once per language, and
 * `getByText('Contradicted')` would pass in English and fail in French — teaching whoever fixed it
 * to assert nothing. They match identifiers and numbers, which are the same in both editions.
 *
 * <h2>Running it</h2>
 *
 * <pre>npx playwright test --project=screens-en --project=screens-fr</pre>
 *
 * <p>The images land in `docs-site/assets/screens/&lt;locale&gt;/`. They are committed: the
 * documentation is built from the repository, and a site that regenerates its own illustrations at
 * publish time would need the whole application to boot inside the docs workflow.
 */

/** Midday, fixed. Any instant would do; what matters is that it never moves. */
const FROZEN = new Date('2026-09-18T12:00:00Z');

const SESSION = {
    token: 'screens-token',
    user: { username: 'c.moreau', role: 'CISO', displayName: 'Claire Moreau', mustChangePassword: false }
};

/** A JSON response for a route, without repeating the envelope each time. */
async function stub(page: Page, pattern: string, body: unknown): Promise<void> {
    await page.route(pattern, (route) =>
        route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) }));
}

/**
 * Everything the shell asks for before any screen does, and a floor under the rest.
 *
 * <p>The catch-all matters more than it looks: a screen that fires one request nobody anticipated
 * would otherwise hang on a pending promise and be captured half-rendered. Answering `[]` or `{}`
 * by shape keeps it whole, and the per-screen stubs below override it.
 */
async function stubEverything(page: Page): Promise<void> {
    // **The catch-all goes first, and that order is the whole trick.** Playwright matches the most
    // recently registered route, so a general pattern added last would swallow every specific stub
    // below it and serve `{}` to screens that need data.
    await page.route('**/api/v1/**', (route) => {
        const url = route.request().url();
        const list = /\/(repositories|containers|issues|agents|teams|users|scans|rule-sets)(\?|$)/.test(url);
        return route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: list ? '[]' : '{}'
        });
    });

    await stub(page, '**/api/v1/auth/methods', { password: true, oidc: false });
    await stub(page, '**/api/v1/auth/me', SESSION.user);
    await page.route('**/api/v1/auth/login', (route) =>
        route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(SESSION) }));
}

/**
 * Signs in against the stub, so the session carries a role.
 *
 * <p><b>The form is driven rather than bypassed, and it has to be.</b> The session lives in
 * memory — a deliberate choice of `SessionStore` — so there is nothing to pre-seed, and the
 * application never asks `/auth/me`. Without a real `open()`, the shell still renders but
 * `canReadGovernance()` is false: the four governance entries vanish from the sidebar and a
 * capture of the statement of applicability silently becomes a capture of a menu that does not
 * offer it.
 *
 * <p>The clock is frozen once the application is up, never before: Angular bootstraps on timers,
 * and a fake clock installed ahead of it stops the framework from starting at all.
 */
async function enterApp(page: Page, locale: 'en' | 'fr'): Promise<void> {
    await page.goto('/login');
    await expect(page.locator('#username')).toBeVisible({ timeout: 60_000 });
    await page.locator('#username').fill(SESSION.user.username);
    await page.locator('#password').locator('input').fill('answered-by-the-stub');
    await page.getByRole('button').filter({ hasText: /sign in|connexion|connecter|se connecter/i }).first().click();

    await expect(page.locator('a[href="/soa"]').first()).toBeVisible({ timeout: 30_000 });

    // **The one place this file does read a label, and it is the point.** The locale is a context
    // property; if it ever stops reaching the i18n service — which falls back on
    // `navigator.language` only because nothing is in `localStorage` — both projects would produce
    // the same English images and nothing else here would notice. Asserting the sidebar's first
    // entry in the expected language is what turns that silent drift into a failed run.
    const expected = locale === 'fr' ? 'Tableau de bord' : 'Dashboard';
    await expect(page.locator('a[href="/dashboard"]').last()).toContainText(expected, { timeout: 15_000 });

    await page.clock.install({ time: FROZEN });
}

/**
 * Opens a screen the way a reader does, and proves the entry exists.
 *
 * <p>By `href` rather than by label: this file runs in two languages, and a selector that reads
 * the menu's words would only ever work in one of them.
 */
async function openScreen(page: Page, path: string): Promise<void> {
    await page.locator(`a[href="${path}"]`).first().click();
    await expect(page).toHaveURL(new RegExp(`${path.replace('/', '\\/')}(\\?|$)`), { timeout: 15_000 });
}

/** Captures the screen, under the locale this project runs in. */
async function shoot(page: Page, name: string, locale: string): Promise<void> {
    await page.screenshot({ path: `../docs-site/assets/screens/${locale}/${name}.png` });
}

/**
 * The edition this run writes, taken from the project name.
 *
 * <p>One set of cases rather than two: the language is a property of the browser context, which a
 * project already configures, so generating a case per locale would only duplicate everything and
 * skip half of it at run time.
 */
const edition = (name: string) => (name === 'screens-fr' ? 'fr' : 'en');

test.describe('documentation screenshots', () => {

        test('exceptions', async ({ page }, testInfo) => {
            const locale = edition(testInfo.project.name);
            await stubEverything(page);
            await stub(page, '**/api/v1/exceptions*', {
                entries: [{
                    issue_id: 41, identifier: 'CVE-2026-0001', severity: 'critical',
                    target_kind: 'REPOSITORY', target_id: 7, target_name: 'portail-client',
                    decision: 'not_affected', justification: 'vulnerable_code_not_in_execute_path',
                    comment: null, actor: 'c.moreau', origin: 'manual',
                    decided_at: '2026-01-12T09:00:00Z', expires_at: '2026-08-12T00:00:00Z',
                    lapsed: true, last_reviewed_at: null, last_reviewed_by: null
                }],
                granted: 1, awaiting_approval: 0, lapsed: 1, never_reviewed: 1
            });
            await enterApp(page, locale);
            await openScreen(page, '/exceptions');

            // On the identifier, not on a label: it reads the same in both editions.
            await expect(page.getByText('CVE-2026-0001')).toBeVisible({ timeout: 15_000 });
            await shoot(page, 'exceptions', locale);
        });

        test('remediation times', async ({ page }, testInfo) => {
            const locale = edition(testInfo.project.name);
            await stubEverything(page);
            await stub(page, '**/api/v1/remediation/distribution*', {
                windowDays: 90, oldestOpenDays: 241, oldestOpenSeverity: 'critical',
                bySeverity: [
                    {
                        severity: 'critical', windowDays: 7, withinSla: 17, late: 11,
                        percentageWithinSla: 61, medianDays: 4.5, ninetiethDays: 38,
                        openOverdue: 5, oldestOpenDays: 241
                    },
                    {
                        severity: 'low', windowDays: 0, withinSla: 0, late: 0,
                        percentageWithinSla: null, medianDays: 21, ninetiethDays: 147,
                        openOverdue: 0, oldestOpenDays: 312
                    }
                ]
            });
            await enterApp(page, locale);
            await openScreen(page, '/remediation-delays');

            await expect(page.getByText('241').first()).toBeVisible({ timeout: 15_000 });
            await shoot(page, 'remediation-times', locale);
        });

        test('statement of applicability', async ({ page }, testInfo) => {
            const locale = edition(testInfo.project.name);
            await stubEverything(page);
            const line = (id: string, divergence: string) => ({
                control: { id, name: id, framework: 'ISO_27001' },
                declaration: {
                    framework: 'ISO_27001', controlId: id, applicability: 'APPLICABLE',
                    justification: 'In scope.', implementation: 'IMPLEMENTED',
                    evidenceSource: 'VECTISPIRE', externalReference: null,
                    owner: 'n.faure', approver: 'c.moreau',
                    decidedAt: '2026-01-05T00:00:00Z', reviewedAt: '2026-06-05T00:00:00Z',
                    nextReviewAt: '2027-06-05T00:00:00Z'
                },
                measured: 'NON_COMPLIANT', divergence, reviewOverdue: false
            });
            await stub(page, '**/api/v1/compliance/soa', [{
                framework: 'ISO_27001', total: 2, declared: 2, findings: 1, reviewsOverdue: 0,
                complete: true,
                lines: [line('ISO-A.5.15', 'CONSISTENT'), line('ISO-A.8.8', 'CONTRADICTED')]
            }]);
            await enterApp(page, locale);
            await openScreen(page, '/soa');

            await expect(page.getByText('ISO-A.8.8').first()).toBeVisible({ timeout: 15_000 });
            await shoot(page, 'statement-of-applicability', locale);
        });
    });
