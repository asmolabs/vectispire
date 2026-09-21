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

/**
 * The account these captures are taken under.
 *
 * <p><b>`ADMIN` rather than `CISO`, and the menu decided it.</b> A CISO reads governance and
 * settles a triage but is not an administrator, so `/users` and `/teams` have no sidebar entry for
 * them — and these captures navigate by clicking, which is the point. `ADMIN` is in all three
 * vocabularies: administrator, security lead, governance reader.
 *
 * <p>It is not `SUPERUSER`: that role governs the platform without acting on it, so a capture
 * taken under it would show a product with its triage missing.
 */
const SESSION = {
    token: 'screens-token',
    user: { username: 'c.moreau', role: 'ADMIN', displayName: 'Claire Moreau', mustChangePassword: false }
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
        // **A collection answered as an object breaks the page before it renders.** `ssh-keys` was
        // missing from this list, so the repositories screen — which loads them for its form —
        // received `{}`, and the table never appeared while the heading did. The fixture was not
        // at fault; this line was.
        const list = /\/(repositories|containers|issues|agents|teams|users|scans|rule-sets|ssh-keys|api-keys|gate-policies|notifications|exceptions|verdicts|keys)(\?|\/|$)/.test(url);
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

/**
 * Captures the screen, under the locale this project runs in.
 *
 * <p><b>A table that has finished loading is still drawing its mask.</b> The overlay fades out on
 * a CSS transition — driven by the compositor, so the frozen clock does not reach it — while the
 * rows are already underneath it. Every assertion here waits on a row, which is therefore
 * satisfied a few frames too early: the `teams` capture shipped with the loading spinner sitting
 * over the cell it hid, and nothing failed.
 *
 * <p>So the mask has to leave before the shot, and what is left of any animation is stopped
 * outright. A screenshot should be a settled screen, not whichever frame the run happened to
 * reach.
 */
async function shoot(page: Page, name: string, locale: string): Promise<void> {
    await expect(page.locator('.p-datatable-mask')).toHaveCount(0, { timeout: 15_000 });
    await page.addStyleTag({
        content: '*, *::before, *::after { animation: none !important; transition: none !important; }'
    });
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
                    target_kind: 'REPOSITORY', target_id: 7, target_name: 'helios-portal',
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

        test('remediation plan', async ({ page }, testInfo) => {
            const locale = edition(testInfo.project.name);
            await stubEverything(page);
            await stub(page, '**/api/v1/remediation/high-impact-fixes*', [{
                packageName: 'log4j-core', currentVersion: '2.14.1', recommendedVersion: '2.17.1',
                cveCountResolved: 12, criticalCveCount: 4, highCveCount: 8,
                estimatedHours: 1.3, leverageScore: 9.2,
                affectedCves: ['CVE-2021-44228'], affectedTargetNames: ['common-libs']
            }]);
            await stub(page, '**/api/v1/remediation/debt*', {
                totalOpenIssues: 412, criticalIssues: 4, highIssues: 8, mediumIssues: 0, lowIssues: 400,
                totalEstimatedHours: 812.3, totalEstimatedPersonDays: 101.5,
                vulnerabilitiesDebtHours: 12.3, secretsDebtHours: 798, sastDebtHours: 0,
                iacDebtHours: 2, licenseDebtHours: 0, eolDebtHours: 0, topHighImpactFixes: []
            });
            // The disproportion this screen exists to explain: one action, and four hundred
            // findings no upgrade closes.
            await stub(page, '**/api/v1/remediation/coverage*', {
                openFindings: 412, addressableByUpgrade: 12, beyondUpgrades: 400,
                gaps: [{ family: 'secret', findings: 399 }, { family: 'unpackaged', findings: 1 }]
            });
            await enterApp(page, locale);
            await openScreen(page, '/remediation');

            await expect(page.getByText('log4j-core').first()).toBeVisible({ timeout: 15_000 });
            await shoot(page, 'remediation-plan', locale);
        });

        test('compliance progress', async ({ page }, testInfo) => {
            const locale = edition(testInfo.project.name);
            await stubEverything(page);
            const month = (period: string, score: number, targets: number, delta: number,
                           movement: string, because: string) => ({
                snapshot: {
                    period, framework: 'ISO_27001', score, status: 'PARTIAL',
                    targets, observed: targets, fresh: targets, freshnessDays: 30,
                    endOfLifeEnabled: true, codeAnalysisReaches: true,
                    controlsTotal: 4, controlsDeclared: 4, soaFindings: 0,
                    capturedAt: `${period}-28T00:00:00Z`
                },
                delta, movement, because
            });
            await stub(page, '**/api/v1/compliance/history', [{
                framework: 'ISO_27001',
                comparable: false,
                steps: [
                    month('2026-07', 90, 10, 0, 'FIRST', 'First capture for this framework.'),
                    month('2026-08', 71, 14, -19, 'ESTATE_GREW',
                          '4 target(s) more than last month. A score that falls here is the cost of watching wider, not a regression.')
                ]
            }]);
            await enterApp(page, locale);
            await openScreen(page, '/compliance-history');

            await expect(page.getByText('2026-08').first()).toBeVisible({ timeout: 15_000 });
            await shoot(page, 'compliance-progress', locale);
        });

        test('certified scope', async ({ page }, testInfo) => {
            const locale = edition(testInfo.project.name);
            await stubEverything(page);
            // Forty declared against thirty-one held: the sentence an audit begins with, and the one
            // no query inside the product can produce on its own.
            await stub(page, '**/api/v1/compliance/scope', {
                statement: 'The customer portal, its build pipeline and the images it ships.',
                coverage: { declaredAssets: 40, inScope: 31, scannedRecently: 20, stale: 11, neverScanned: 0 },
                targets: []
            });
            await enterApp(page, locale);
            await openScreen(page, '/certified-scope');

            await expect(page.getByText('40').first()).toBeVisible({ timeout: 15_000 });
            await shoot(page, 'certified-scope', locale);
        });

        test('EPSS prioritisation', async ({ page }, testInfo) => {
            const locale = edition(testInfo.project.name);
            await stubEverything(page);
            // `recommendedAction` is a token since this week; the screen turns it into a sentence in
            // the reader's language, which is exactly what a bilingual screenshot should show.
            await stub(page, '**/api/v1/epss/priorities', {
                totalVulnerabilities: 412, activeKevCount: 3, highEpssCount: 11,
                reachableEpssCount: 6, averageFleetEpss: 0.07,
                breakdownByTier: { CRITICAL_ARMED: 3, HIGH_PROBABLE: 8, MEDIUM_THEORETICAL: 41, LOW_PROBABILITY: 360 },
                topPriorities: [
                    {
                        issueId: 41, identifier: 'CVE-2021-44228', title: 'Log4Shell',
                        severity: 'critical', cvssScore: 10.0, epssScore: 0.975, epssPercentile: 0.999,
                        isKev: true, reachability: 'REACHABLE', targetName: 'helios-portal',
                        targetKind: 'REPOSITORY', priorityScore: 98, priorityTier: 'CRITICAL_ARMED',
                        recommendedAction: 'P0_KEV_24H'
                    },
                    {
                        issueId: 42, identifier: 'CVE-2024-1086', title: 'Kernel use-after-free',
                        severity: 'high', cvssScore: 7.8, epssScore: 0.41, epssPercentile: 0.97,
                        isKev: false, reachability: 'UNKNOWN', targetName: 'basalt-libs',
                        targetKind: 'REPOSITORY', priorityScore: 64, priorityTier: 'HIGH_PROBABLE',
                        recommendedAction: 'P1_7D'
                    }
                ]
            });
            await enterApp(page, locale);
            await openScreen(page, '/epss');

            await expect(page.getByText('CVE-2021-44228').first()).toBeVisible({ timeout: 15_000 });
            await shoot(page, 'epss', locale);
        });


        test('SBOM comparison', async ({ page }, testInfo) => {
            const locale = edition(testInfo.project.name);
            await stubEverything(page);
            await stub(page, '**/api/v1/repositories*', [
                { id: 5, name: 'helios-portal', url: 'ssh://git@example.invalid/helios-portal.git', branch: 'main' }
            ]);
            // The history the two pickers read. It replaced two number fields asking for internal
            // identifiers, so a capture showing dates is the whole point of the change.
            await stub(page, '**/api/v1/scans*', [
                { id: 34, status: 'completed', branch: 'main', targetKind: 'REPOSITORY',
                  targetName: 'helios-portal', createdAt: '2026-09-17T21:04:00Z', durationMs: 91_000,
                  findingsCount: 7, newIssuesCount: 1, resolvedIssuesCount: 3, error: null,
                  claimedBy: null, attempts: 1, targetId: 5 },
                { id: 33, status: 'completed', branch: 'main', targetKind: 'REPOSITORY',
                  targetName: 'helios-portal', createdAt: '2026-09-10T21:03:00Z', durationMs: 88_000,
                  findingsCount: 9, newIssuesCount: 0, resolvedIssuesCount: 0, error: null,
                  claimedBy: null, attempts: 1, targetId: 5 }
            ]);
            await enterApp(page, locale);
            await openScreen(page, '/inventory');

            // The comparison is the second tab; by position, because the label is translated.
            await page.getByRole('button').filter({ hasText: /SBOM|diff|comparaison/i }).first().click();
            await page.locator('#diff-target').click();
            await page.getByRole('option').filter({ hasText: 'helios-portal' }).first().click();

            // The two most recent are preselected, so the screen answers "since last time" before
            // anybody clicks. A capture of two empty pickers would be a capture of the old defect.
            await expect(page.getByText('#34').first()).toBeVisible({ timeout: 15_000 });
            await shoot(page, 'sbom-comparison', locale);
        });

        test('dashboard', async ({ page }, testInfo) => {
            const locale = edition(testInfo.project.name);
            await stubEverything(page);
            await stub(page, '**/api/v1/dashboard', {
                posture: { totalCount: 14, failingCount: 3, kevCount: 2, overdueCount: 5,
                           neverScannedCount: 1, lastScanFailedCount: 1 },
                backlogBySeverity: { CRITICAL: 4, HIGH: 12, MEDIUM: 31, LOW: 365 },
                failing: [
                    { kind: 'repository', targetId: 5, name: 'helios-portal', violations: [] },
                    { kind: 'container', targetId: 3, name: 'registry.example/api:1.4', violations: [] }
                ],
                recentScans: [
                    { id: 34, status: 'completed', targetKind: 'repository', targetName: 'helios-portal',
                      repoId: 5, containerId: null, error: null, createdAt: '2026-09-17T21:04:00Z' },
                    { id: 33, status: 'failed', targetKind: 'repository', targetName: 'basalt-libs',
                      repoId: 6, containerId: null, error: 'clone refused', createdAt: '2026-09-17T03:10:00Z' }
                ]
            });
            // Two charts rather than two axes: the backlog and the daily movements differ by two
            // orders of magnitude, so the capture has to show both curves readable.
            await stub(page, '**/api/v1/dashboard/trends*', {
                points: [
                    { day: '2026-09-12', open: 402, opened: 9, resolved: 2 },
                    { day: '2026-09-13', open: 405, opened: 5, resolved: 2 },
                    { day: '2026-09-14', open: 399, opened: 1, resolved: 7 },
                    { day: '2026-09-15', open: 404, opened: 8, resolved: 3 },
                    { day: '2026-09-16', open: 410, opened: 9, resolved: 3 },
                    { day: '2026-09-17', open: 412, opened: 6, resolved: 4 }
                ],
                mean_days_to_resolve: 11.4,
                resolved_in_window: 21
            });
            await enterApp(page, locale);
            await openScreen(page, '/dashboard');

            await expect(page.getByText('helios-portal').first()).toBeVisible({ timeout: 15_000 });
            await shoot(page, 'dashboard', locale);
        });

        test('issues', async ({ page }, testInfo) => {
            const locale = edition(testInfo.project.name);
            await stubEverything(page);
            const issue = (id: number, identifier: string, severity: string, pkg: string,
                           version: string, target: string) => ({
                id, targetKind: 'repository', type: 'vulnerability', state: 'open',
                firstSeenAt: '2026-08-21T07:57:53Z', lastSeenAt: '2026-09-17T21:04:00Z',
                triageStatus: 'under_review', repoId: 5, containerId: null, targetName: target,
                identifier, severity, packageName: pkg, packageVersion: version,
                purl: `pkg:maven/${pkg}@${version}`, filePath: null, line: null
            });
            await stub(page, '**/api/v1/issues*', {
                items: [
                    issue(41, 'CVE-2021-44228', 'critical', 'log4j-core', '2.14.1', 'helios-portal'),
                    issue(42, 'CVE-2024-1086', 'high', 'linux-libc-dev', '6.1.0', 'registry.example/api:1.4'),
                    issue(43, 'CVE-2023-44487', 'medium', 'netty-codec-http2', '4.1.94', 'basalt-libs')
                ],
                total: 412, limit: 25, offset: 0
            });
            await enterApp(page, locale);
            await openScreen(page, '/issues');

            await expect(page.getByText('CVE-2021-44228').first()).toBeVisible({ timeout: 15_000 });
            await shoot(page, 'issues', locale);
        });



        test('attack paths', async ({ page }, testInfo) => {
            const locale = edition(testInfo.project.name);
            await stubEverything(page);
            await stub(page, '**/api/v1/repositories*', [
                { id: 5, url: 'ssh://git@example.invalid/helios-portal.git', branch: 'main',
                  displayName: 'helios-portal', name: 'helios-portal', subPath: null }
            ]);
            // Node notes and the scenario are tokens since this week: the graph and its narrative
            // are written by the screen, so the two editions differ throughout.
            const graph = {
                targetId: 5, targetName: 'helios-portal',
                nodes: [
                    { id: 'ingress', label: 'Internet Ingress (0.0.0.0/0)', type: 'INTERNET_INGRESS',
                      severity: 'INFO', isExploitable: true, note: 'PUBLIC_INGRESS', metadata: {} },
                    { id: 'ep-1', label: 'GET /api/admin/users', type: 'API_ENDPOINT',
                      severity: 'CRITICAL', isExploitable: true, note: 'UNAUTHENTICATED_ROUTE', metadata: {} },
                    { id: 'vuln-1', label: 'CVE-2021-44228', type: 'VULNERABLE_COMPONENT',
                      severity: 'CRITICAL', isExploitable: true, note: 'RCE_ACTIVELY_EXPLOITED',
                      metadata: { cvss: '10.0' } },
                    { id: 'db', label: 'Database / Production Data Sink', type: 'DATABASE',
                      severity: 'CRITICAL', isExploitable: true, note: 'SENSITIVE_DATA_STORE', metadata: {} }
                ],
                edges: [
                    { id: 'e1', source: 'ingress', target: 'ep-1', label: 'REACHES', isCritical: true },
                    { id: 'e2', source: 'ep-1', target: 'vuln-1', label: 'INVOKES', isCritical: true },
                    { id: 'e3', source: 'vuln-1', target: 'db', label: 'EXFILTRATES_DATA', isCritical: true }
                ],
                attackPaths: [{
                    id: 'path-rce-exfil', scenario: 'UNAUTH_RCE_CHAIN',
                    params: { method: 'GET', path: '/api/admin/users',
                              identifier: 'CVE-2021-44228', package: 'log4j-core' },
                    riskLevel: 'CRITICAL', isDirectlyExploitable: true,
                    nodeIds: ['ingress', 'ep-1', 'vuln-1', 'db']
                }]
            };
            await stub(page, '**/api/v1/attack-paths/overview', [graph]);
            await stub(page, '**/api/v1/attack-paths/repositories/**', graph);
            await enterApp(page, locale);
            await openScreen(page, '/attack-paths');

            await expect(page.getByText('CVE-2021-44228').first()).toBeVisible({ timeout: 15_000 });
            await shoot(page, 'attack-paths', locale);
        });

        test('repositories', async ({ page }, testInfo) => {
            const locale = edition(testInfo.project.name);
            await stubEverything(page);
            // **Shaped from `openapi.json`, not from memory.** A first attempt guessed the fields
            // and the table never rendered: `openIssues` is required and was missing, and the
            // criticality is `tier`. Reading the contract is how a fixture stops being a second
            // opinion about the server.
            await stub(page, '**/api/v1/repositories*', [
                { id: 5, url: 'ssh://git@example.invalid/helios-portal.git', branch: 'main',
                  displayName: 'helios-portal', name: 'helios-portal', subPath: null,
                  openIssues: 214, tier: 'TIER_1', scanIntervalMinutes: 1440, scanCron: null,
                  sshKeyId: null, requiredAgentLabel: null, lastScheduledScanAt: '2026-09-17T21:00:00Z',
                  lastScan: { id: 34, status: 'completed', createdAt: '2026-09-17T21:04:00Z', error: null } },
                { id: 6, url: 'ssh://git@example.invalid/basalt-libs.git', branch: 'master',
                  displayName: 'basalt-libs', name: 'basalt-libs', subPath: null,
                  openIssues: 37, tier: 'TIER_3', scanIntervalMinutes: null, scanCron: '0 3 * * *',
                  sshKeyId: null, requiredAgentLabel: null, lastScheduledScanAt: '2026-09-16T03:00:00Z',
                  lastScan: { id: 30, status: 'failed', createdAt: '2026-09-16T03:11:00Z',
                              error: 'clone refused' } }
            ]);
            await enterApp(page, locale);
            await openScreen(page, '/repositories');

            await expect(page.getByText('basalt-libs').first()).toBeVisible({ timeout: 15_000 });
            await shoot(page, 'repositories', locale);
        });

        test('containers', async ({ page }, testInfo) => {
            const locale = edition(testInfo.project.name);
            await stubEverything(page);
            // One image pinned by digest, because the shortening only exists for that case: sixty
            // characters of hexadecimal push every other field off the card, and a capture of
            // three tag-pinned images would show a screen that never has to deal with it.
            await stub(page, '**/api/v1/containers*', [
                { id: 3, imageName: 'registry.example/api', tag: '1.4',
                  reference: 'registry.example/api:1.4', registry: 'registry.example',
                  openIssues: 58, tier: 'TIER_1_MISSION_CRITICAL',
                  scanIntervalMinutes: 720, scanCron: null, requiredAgentLabel: null,
                  lastScheduledScanAt: '2026-09-17T18:00:00Z',
                  lastScan: { id: 32, status: 'completed', createdAt: '2026-09-17T18:06:00Z', error: null } },
                { id: 4, imageName: 'registry.example/nginx-edge', tag: 'sha256:9f2c1d4b7a03e85f6c2b9d10a47e3f8521bc60d9e7a4f31682c5b0ad9e14f7c3',
                  reference: 'registry.example/nginx-edge@sha256:9f2c1d4b7a03e85f6c2b9d10a47e3f8521bc60d9e7a4f31682c5b0ad9e14f7c3',
                  registry: 'registry.example', openIssues: 0, tier: 'TIER_2_BUSINESS_OPERATIONAL',
                  scanIntervalMinutes: null, scanCron: '0 4 * * *', requiredAgentLabel: 'dmz',
                  lastScheduledScanAt: '2026-09-18T04:00:00Z',
                  lastScan: { id: 35, status: 'completed', createdAt: '2026-09-18T04:03:00Z', error: null } },
                { id: 5, imageName: 'registry.example/batch-runner', tag: '2026.09',
                  reference: 'registry.example/batch-runner:2026.09', registry: 'registry.example',
                  openIssues: 12, tier: 'TIER_3_INTERNAL',
                  scanIntervalMinutes: null, scanCron: null, requiredAgentLabel: null,
                  lastScheduledScanAt: null,
                  lastScan: { id: 31, status: 'failed', createdAt: '2026-09-16T11:20:00Z',
                              error: 'manifest unknown' } }
            ]);
            await enterApp(page, locale);
            await openScreen(page, '/containers');

            await expect(page.getByText('registry.example/batch-runner').first()).toBeVisible({ timeout: 15_000 });
            await shoot(page, 'containers', locale);
        });

        test('code quality', async ({ page }, testInfo) => {
            const locale = edition(testInfo.project.name);
            await stubEverything(page);
            // **Partial coverage, not full.** The banner is the screen's one warning, and a capture
            // taken over a covered estate would hide it: a quality backlog is only as complete as
            // the languages somebody wrote rules for, and TypeScript having none is exactly the
            // thing a reader should learn here rather than discover later.
            await stub(page, '**/api/v1/rule-sets/coverage', {
                state: 'PARTIAL', ruleFiles: 12,
                languagesWithRules: ['java', 'python'],
                ecosystemsInEstate: ['java', 'python', 'typescript'],
                uncovered: ['typescript']
            });
            // The three tallies are deliberately top-heavy. "Eight rules account for most of the
            // debt" is the framing this page exists for, and a flat distribution would illustrate
            // the opposite of its argument.
            await stub(page, '**/api/v1/quality/overview', {
                openCount: 1432, ruleCount: 47, fileCount: 318,
                topRules: [
                    { label: 'java.lang.security.audit.formatted-sql-string', count: 212 },
                    { label: 'python.lang.correctness.unchecked-subprocess', count: 164 },
                    { label: 'java.lang.maintainability.dead-catch-block', count: 121 },
                    { label: 'generic.secrets.hardcoded-token', count: 38 }
                ],
                topFiles: [
                    { label: 'src/main/java/portal/LegacyQueryBuilder.java', count: 96 },
                    { label: 'src/main/java/portal/ReportExporter.java', count: 71 },
                    { label: 'scripts/migrate_accounts.py', count: 44 },
                    { label: 'src/main/java/portal/AuditTrail.java', count: 22 }
                ],
                topTargets: [
                    { label: 'helios-portal', count: 731 },
                    { label: 'basalt-libs', count: 402 },
                    { label: 'billing-legacy', count: 299 }
                ]
            });
            await stub(page, '**/api/v1/dashboard', {
                posture: { totalCount: 14, failingCount: 3, kevCount: 2, overdueCount: 5,
                           neverScannedCount: 1, lastScanFailedCount: 1 },
                backlogBySeverity: { CRITICAL: 4, HIGH: 12, MEDIUM: 31, LOW: 365 },
                qualityTotal: 1432, failing: [], recentScans: []
            });
            await enterApp(page, locale);
            // **Through the dashboard, because the sidebar does not offer this screen.** Quality
            // is reached from the backlog card's quality total and from nowhere else, so a capture
            // that clicked a menu entry would be asserting a route that no reader can take.
            //
            // And not through `openScreen`, because that link carries no `href`: written
            // `routerLink="/quality"` rather than `[routerLink]="['/quality']"`, it navigates on
            // click and renders no address. Clicking the total is what a reader does; the URL
            // assertion below is what keeps this honest if the route is ever renamed.
            await openScreen(page, '/dashboard');
            await page.getByText('1432').first().click();
            await expect(page).toHaveURL(/\/quality(\?|$)/, { timeout: 15_000 });

            await expect(page.getByText('1432').first()).toBeVisible({ timeout: 15_000 });
            await shoot(page, 'code-quality', locale);
        });

        test('gate policies', async ({ page }, testInfo) => {
            const locale = edition(testInfo.project.name);
            await stubEverything(page);
            // **The stored policy departs from the built-in on two flags, and that is the point of
            // the fixture.** Identical cards would photograph the screen's argument out of it:
            // showing both is the only place "not set" and "set to the same thing" can be told
            // apart, and a capture where they read alike demonstrates nothing.
            await stub(page, '**/api/v1/gate/policies', {
                policies: [
                    { kind: 'global', target_id: null, target_name: null, version: 4,
                      fail_on_severity: 'high', fail_on_kev: true, fixable_only: true,
                      include_triaged: false, include_ai_review: false,
                      fail_on_uncovered_languages: false,
                      note: 'criticals in transitive dependencies were failing every build and teams had started bypassing the gate',
                      created_by: 'c.moreau', created_at: '2026-08-02T09:12:00Z' },
                    { kind: 'repository', target_id: 5, target_name: 'helios-portal', version: 2,
                      fail_on_severity: 'medium', fail_on_kev: true, fixable_only: false,
                      include_triaged: false, include_ai_review: false,
                      fail_on_uncovered_languages: false,
                      note: 'Tier 1 payment path, held above the estate bar for the quarter',
                      created_by: 'c.moreau', created_at: '2026-09-04T16:40:00Z' }
                ],
                built_in: { kind: 'built-in', target_id: null, target_name: null, version: 0,
                            fail_on_severity: 'high', fail_on_kev: true, fixable_only: false,
                            include_triaged: false, include_ai_review: false,
                            fail_on_uncovered_languages: false, note: null,
                            created_by: null, created_at: null }
            });
            await enterApp(page, locale);
            await openScreen(page, '/gate-policies');

            await expect(page.getByText('helios-portal').first()).toBeVisible({ timeout: 15_000 });
            await shoot(page, 'gate-policies', locale);
        });

        test('security overview', async ({ page }, testInfo) => {
            const locale = edition(testInfo.project.name);
            await stubEverything(page);
            // The two cases no other screen names: a target never scanned, and one whose last scan
            // failed. Both are green everywhere else, which is the point of this page.
            //
            // **Shaped as `SecurityOverviewView` writes it, which the first version was not.**
            // That fixture sent `NEVER_SCANNED` and invented `FRESH` and `STALE`; the server
            // lowercases every constant and has only four — the view class says so in as many
            // words, and warns that a client comparing against `never_scanned` matches nothing
            // and renders its fallback. It did: the never-scanned target was captured badged
            // "scan in progress". It also sent `verdict: null`, which no target ever carries —
            // the server evaluates a policy against an empty backlog rather than skipping it —
            // and the row that received it rendered as a line of blanks.
            await stub(page, '**/api/v1/security/overview*', {
                totalCount: 4, failingCount: 1, kevCount: 1,
                neverScannedCount: 1, lastScanFailedCount: 1,
                targets: [
                    { targetId: 5, kind: 'repository', name: 'helios-portal', observed: true,
                      passed: false, lastScanAt: '2026-09-17T21:04:00Z', lastScanId: 34,
                      observation: 'ok',
                      policy: { source: 'built-in', version: null },
                      verdict: { passed: false, evaluated: 412, violations: [],
                                 countsBySeverity: { CRITICAL: 1, HIGH: 3 } } },
                    { targetId: 6, kind: 'repository', name: 'basalt-libs', observed: false,
                      passed: true, lastScanAt: '2026-09-16T03:11:00Z', lastScanId: 30,
                      observation: 'last_scan_failed',
                      policy: { source: 'built-in', version: null },
                      verdict: { passed: true, evaluated: 37, violations: [], countsBySeverity: {} } },
                    // Passing on nothing at all: the empty backlog that satisfies every policy,
                    // which is the whole reason the observation column exists.
                    { targetId: 7, kind: 'repository', name: 'billing-legacy', observed: false,
                      passed: true, lastScanAt: null, lastScanId: null,
                      observation: 'never_scanned',
                      policy: { source: 'built-in', version: null },
                      verdict: { passed: true, evaluated: 0, violations: [], countsBySeverity: {} } }
                ]
            });
            await enterApp(page, locale);
            await openScreen(page, '/security');

            await expect(page.getByText('billing-legacy').first()).toBeVisible({ timeout: 15_000 });
            await shoot(page, 'security-overview', locale);
        });

        test('gate verdicts', async ({ page }, testInfo) => {
            const locale = edition(testInfo.project.name);
            await stubEverything(page);
            // A refusal is the only proof a control runs: "everything passes" does not tell a clean
            // estate from a gate that never blocked anything.
            await stub(page, '**/api/v1/gate/verdicts*', {
                passed: 128, refused: 6, next_cursor: null,
                verdicts: [
                    { id: '0195f3a1-8a2b-7c4d-9e1f-2a3b4c5d6e7f', target_kind: 'repository', target_id: 5,
                      passed: false, evaluated: 412, violations: 4, fail_on_severity: 'high',
                      policy_source: 'built-in', policy_version: null, relaxations_ignored: false,
                      counts_by_severity: { CRITICAL: 1, HIGH: 3 },
                      decided_at: '2026-09-17T21:05:00Z', decided_by: 'ci' },
                    { id: '0195f3a1-8a2b-7c4d-9e1f-2a3b4c5d6e80', target_kind: 'repository', target_id: 6,
                      passed: true, evaluated: 37, violations: 0, fail_on_severity: 'high',
                      policy_source: 'built-in', policy_version: null, relaxations_ignored: false,
                      counts_by_severity: {},
                      decided_at: '2026-09-16T03:12:00Z', decided_by: 'ci' }
                ]
            });
            await enterApp(page, locale);
            await openScreen(page, '/gate-verdicts');

            await expect(page.getByText('412').first()).toBeVisible({ timeout: 15_000 });
            await shoot(page, 'gate-verdicts', locale);
        });

        test('audit log', async ({ page }, testInfo) => {
            const locale = edition(testInfo.project.name);
            await stubEverything(page);
            // Each entry carries the hash of the one before it, which is what makes a deletion
            // visible rather than merely forbidden.
            await stub(page, '**/api/v1/audit-log*', {
                total: 3, limit: 25, offset: 0,
                items: [
                    { id: '0195f3a1-0001', timestamp: '2026-09-17T21:06:00Z', userId: 'c.moreau',
                      operationType: 'TRIAGE_DECIDED', resourceId: 'issue:41',
                      description: 'CVE-2021-44228 marked under review on helios-portal',
                      ipAddress: '10.0.2.14', userAgent: 'Mozilla/5.0',
                      entryHash: '9f2c…a71b', previousHash: '4d81…ee02' },
                    { id: '0195f3a1-0002', timestamp: '2026-09-17T20:41:00Z', userId: 'n.faure',
                      operationType: 'SETTING_CHANGED', resourceId: 'four_eyes_approval_required',
                      description: 'Four-eyes approval switched on',
                      ipAddress: '10.0.2.9', userAgent: 'Mozilla/5.0',
                      entryHash: '4d81…ee02', previousHash: '1a05…77c3' },
                    { id: '0195f3a1-0003', timestamp: '2026-09-17T19:02:00Z', userId: 'ci',
                      operationType: 'GATE_EVALUATED', resourceId: 'repository:5',
                      description: 'Gate refused: 4 violations above high',
                      ipAddress: '10.0.9.3', userAgent: 'vectispire-cli/0.9.0',
                      entryHash: '1a05…77c3', previousHash: null }
                ]
            });
            await enterApp(page, locale);
            await openScreen(page, '/audit-log');

            await expect(page.getByText('c.moreau').first()).toBeVisible({ timeout: 15_000 });
            await shoot(page, 'audit-log', locale);
        });

        test('users', async ({ page }, testInfo) => {
            const locale = edition(testInfo.project.name);
            await stubEverything(page);
            await stub(page, '**/api/v1/users*', {
                currentUserId: 2,
                users: [
                    { id: 1, username: 'admin', displayName: 'Bootstrap account', email: null,
                      role: 'SUPERUSER', isActive: true, mustChangePassword: false,
                      activeSessions: 0, createdAt: '2026-04-23T08:00:00Z' },
                    { id: 2, username: 'c.moreau', displayName: 'Claire Moreau',
                      email: 'c.moreau@example.invalid', role: 'CISO', isActive: true,
                      mustChangePassword: false, activeSessions: 1, createdAt: '2026-05-02T09:10:00Z' },
                    { id: 3, username: 'n.faure', displayName: 'Noé Faure',
                      email: 'n.faure@example.invalid', role: 'AUDITOR', isActive: true,
                      mustChangePassword: false, activeSessions: 0, createdAt: '2026-06-11T14:25:00Z' }
                ]
            });
            await enterApp(page, locale);
            await openScreen(page, '/users');

            await expect(page.getByText('c.moreau').first()).toBeVisible({ timeout: 15_000 });
            await shoot(page, 'users', locale);
        });

        test('teams', async ({ page }, testInfo) => {
            const locale = edition(testInfo.project.name);
            await stubEverything(page);
            await stub(page, '**/api/v1/teams*', [
                { id: 1, name: 'AppSec', description: 'Reviews and triage', memberCount: 4,
                  targetCount: 11, notified: true },
                { id: 2, name: 'Paiements', description: 'Tier 1 payment path', memberCount: 6,
                  targetCount: 3, notified: false }
            ]);
            await enterApp(page, locale);
            await openScreen(page, '/teams');

            await expect(page.getByText('AppSec').first()).toBeVisible({ timeout: 15_000 });
            await shoot(page, 'teams', locale);
        });

        test('attestation', async ({ page }, testInfo) => {
            const locale = edition(testInfo.project.name);
            await stubEverything(page);
            // The chain leads because it is the only claim on that page which demonstrates itself.
            // `unverifiable` counts entries written before chaining existed: history, not tampering.
            await stub(page, '**/api/v1/audit-log/verify', {
                intact: true, broken: null, total: 1284, verified: 1240, unverifiable: 44,
                mirrored: true, missingFromMirror: 0, missingFromTable: 0
            });
            await stub(page, '**/api/v1/compliance/summary*', {
                totalMonitoredTargets: 14, observedTargets: 13, freshTargets: 11,
                passingGateTargets: 11, overdueCount: 5, dueSoonCount: 2,
                mttr: null, evaluations: [], targets: []
            });
            await enterApp(page, locale);
            await openScreen(page, '/attestation');

            await expect(page.getByText('1284').first()).toBeVisible({ timeout: 15_000 });
            await shoot(page, 'attestation', locale);
        });

        test('ssh keys', async ({ page }, testInfo) => {
            const locale = edition(testInfo.project.name);
            await stubEverything(page);
            // **One key per encryption state, because the column exists for the two that are not
            // `current`.** `SshKeySummary` says so: a key readable only under a previous key has
            // not finished being rotated, and one that no configured key reads will fail the next
            // clone that needs it — at scan time, in a worker thread, hours later. A capture of
            // three healthy keys would photograph a column with nothing to say.
            //
            // The three values are what the server emits and not what reads well: it lowercases
            // `SecretState`, so `current`, `previous_key` and `unreadable`. `badge()` falls back
            // to `unreadable` for anything it does not know, which means a wrong constant here
            // would render the alarming badge on a healthy key and nothing would fail.
            await stub(page, '**/api/v1/ssh-keys', [
                { id: '0f1c9d2a-4b77-4c81-9a10-2e6b5d3f8c40', name: 'gitlab-deploy',
                  publicKey: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB7kQ2vN8pXcR4mL0aYtZ9wFsJ3hG6dK1nP5rT8uV2xE deploy@vectispire',
                  createdAt: '2026-06-14T09:20:00Z', encryptionState: 'current', usedByRepositories: 9 },
                { id: '7a3e5b18-92cd-4f60-8b21-0c4d7e9a1f35', name: 'github-mirror',
                  publicKey: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC2fH9jK4mQ8sW1nB6vX0pL7tR3gY5dZ8cA4eN6uT1oP mirror@vectispire',
                  createdAt: '2026-03-02T14:05:00Z', encryptionState: 'previous_key', usedByRepositories: 3 },
                // Nothing else on this screen would say that a scan is going to fail: the key is
                // present, named, and attached to a repository. Only the badge knows.
                { id: 'c5d81e60-3f24-4a97-b0e8-6d1a2c7b4938', name: 'bitbucket-legacy',
                  publicKey: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAID8bV3xM7qJ0nR5wC1tY6hL9kF2sG4pZ7eB0aU5dN3iQ legacy@vectispire',
                  createdAt: '2025-11-19T08:41:00Z', encryptionState: 'unreadable', usedByRepositories: 1 }
            ]);
            await enterApp(page, locale);
            await openScreen(page, '/ssh-keys');

            await expect(page.getByText('bitbucket-legacy').first()).toBeVisible({ timeout: 15_000 });
            await shoot(page, 'ssh-keys', locale);
        });

        test('api keys', async ({ page }, testInfo) => {
            const locale = edition(testInfo.project.name);
            await stubEverything(page);
            // **`/targets` is an object and the catch-all would answer it `[]`.** The pattern list
            // in `stubEverything` marks anything under `api-keys/` as a collection, so the picker
            // would receive an array and the form would break — the same shape mismatch the
            // `ssh-keys` note in that function describes. Stubbed here rather than fixed there:
            // the catch-all is a floor, and a screen that needs a shape says so itself.
            await stub(page, '**/api/v1/api-keys/targets', {
                repositories: [{ id: 5, label: 'helios-portal' }, { id: 6, label: 'basalt-libs' }],
                containers: [{ id: 3, label: 'registry.example/api' }]
            });
            // Four keys, four things the screen has to be able to say. An unrestricted key and a
            // restricted one, because "all targets" is the dangerous default and it has to be
            // visibly different from a scope. A key never used, because `lastUsedAt` null is not
            // the same as a key used long ago. And an expired one, because `isExpired` is the
            // only reason a key that still exists stops working.
            await stub(page, '**/api/v1/api-keys', [
                { id: '2b9f4c31-8a05-4e72-9d16-3f7c0b5a8e24', name: 'ci-pipeline',
                  prefix: 'vsp_7Kq2', scopes: ['read', 'scan'],
                  targetKind: null, targetId: null, targetLabel: null,
                  createdAt: '2026-07-01T10:00:00Z', lastUsedAt: '2026-09-18T07:42:00Z',
                  expiresAt: null, isExpired: false },
                { id: '8e1a7d52-6c39-4b80-a24f-9b3e5c1d0f67', name: 'helios-gate',
                  prefix: 'vsp_Rm9x', scopes: ['read'],
                  targetKind: 'repository', targetId: 5, targetLabel: 'helios-portal',
                  createdAt: '2026-08-12T16:30:00Z', lastUsedAt: '2026-09-17T22:11:00Z',
                  expiresAt: '2026-11-12T16:30:00Z', isExpired: false },
                // `agent` is the one scope `ApiKeyScope.defaults()` withholds: it is what a remote
                // agent authenticates with, not something a pipeline should be handed by accident.
                { id: 'd4c60b93-1f78-42ae-8506-7a2d9e4b3c18', name: 'dmz-agent',
                  prefix: 'vsp_Lp3T', scopes: ['agent'],
                  targetKind: null, targetId: null, targetLabel: null,
                  createdAt: '2026-05-20T11:15:00Z', lastUsedAt: null,
                  expiresAt: null, isExpired: false },
                { id: '5f27e8a0-9d14-4c63-b7f2-0e8a1b6d5943', name: 'audit-export-q2',
                  prefix: 'vsp_Wd8n', scopes: ['read', 'export'],
                  targetKind: 'container', targetId: 3, targetLabel: 'registry.example/api',
                  createdAt: '2026-04-03T09:00:00Z', lastUsedAt: '2026-06-30T18:20:00Z',
                  expiresAt: '2026-07-01T09:00:00Z', isExpired: true }
            ]);
            await enterApp(page, locale);
            await openScreen(page, '/api-keys');

            await expect(page.getByText('audit-export-q2').first()).toBeVisible({ timeout: 15_000 });
            await shoot(page, 'api-keys', locale);
        });

        test('agents', async ({ page }, testInfo) => {
            const locale = edition(testInfo.project.name);
            await stubEverything(page);
            // **`/activity` is an object, and the catch-all answers `[]` to anything under
            // `agents/`.** Same floor, same reason as `/api-keys/targets` above.
            //
            // The queue is the argument of this screen. `stats` is built so that the three KPI
            // tiles disagree with each other: agents are online, one scan is running, and three
            // are pending — which is the shape of a queue that is not draining, and the shape no
            // single number on the page would show.
            await stub(page, '**/api/v1/admin/agents/activity', {
                stats: { totalAgents: 3, onlineAgents: 2, busyAgents: 1, idleAgents: 1,
                         runningScansCount: 1, pendingScansCount: 3,
                         scansCompleted24h: 47, avgScanDurationSeconds: 214 },
                runningScans: [
                    { scanId: 41, targetId: 5, targetName: 'helios-portal', targetType: 'repository',
                      branch: 'main', agentId: '3c8f1b27-5d40-4e96-a1b8-7f2e0c9d6a53',
                      agentName: 'dmz-runner', requiredLabel: 'dmz',
                      claimedAt: '2026-09-18T11:52:00Z', durationSeconds: 480 }
                ],
                // The third pending scan asks for `airgap`, which no agent below carries. It sits
                // in the queue behind two that will drain, and nothing about it looks different —
                // that is what the unroutable notice is for, and why it is stubbed as well.
                pendingScans: [
                    { scanId: 42, targetId: 6, targetName: 'basalt-libs', targetType: 'repository',
                      branch: 'develop', requiredLabel: null, positionInQueue: 1,
                      queuedAt: '2026-09-18T11:55:00Z', waitDurationSeconds: 300, isRoutable: true },
                    { scanId: 43, targetId: 3, targetName: 'registry.example/api', targetType: 'container',
                      branch: null, requiredLabel: 'dmz', positionInQueue: 2,
                      queuedAt: '2026-09-18T11:57:00Z', waitDurationSeconds: 180, isRoutable: true },
                    { scanId: 44, targetId: 7, targetName: 'billing-legacy', targetType: 'repository',
                      branch: 'main', requiredLabel: 'airgap', positionInQueue: 3,
                      queuedAt: '2026-09-18T09:10:00Z', waitDurationSeconds: 10_200, isRoutable: false }
                ]
            });
            await stub(page, '**/api/v1/admin/agents/non-routables', [{ label: 'airgap', queued: 1 }]);
            // **`kind` and `credentialsMode` are lowercase wire names, not the enum constants.**
            // `AgentKind` and `CredentialsMode` both derive theirs with `name().toLowerCase()`, and
            // the template compares against the literal `'delegated'` — so `DELEGATED` here would
            // silently render every agent as using local keys, which is the reassuring answer.
            await stub(page, '**/api/v1/admin/agents', [
                { id: '1a4e7c90-2b63-4d15-8f07-6c3a9e2b5d81', name: 'built-in worker',
                  description: 'Runs inside the control plane', kind: 'builtin', enabled: true,
                  credentialsMode: 'local', labels: '', sealsCredentials: false, signsResults: false,
                  maxConcurrent: 2, hostname: 'vectispire-control-plane', platform: 'linux/amd64',
                  version: '1.4.0', contractVersion: '2', lastSeenAt: '2026-09-18T11:59:30Z',
                  online: true, runningScans: 0 },
                { id: '3c8f1b27-5d40-4e96-a1b8-7f2e0c9d6a53', name: 'dmz-runner',
                  description: 'Perimeter network', kind: 'remote', enabled: true,
                  credentialsMode: 'delegated', labels: 'dmz', sealsCredentials: true, signsResults: true,
                  maxConcurrent: 4, hostname: 'runner-dmz-01', platform: 'linux/amd64',
                  version: '1.4.0', contractVersion: '2', lastSeenAt: '2026-09-18T11:59:50Z',
                  online: true, runningScans: 1 },
                // **Enabled and silent, which is the case the screen exists to make visible.**
                // `AgentSummary` says it in as many words: an enabled agent that has been silent
                // for an hour is what matters, because the queue fills and nobody drains it.
                // It is also delegated *without* sealing — so the deployment key would cross its
                // proxy in the clear — and it does not sign its results, which is the other thing
                // an operator has no way to discover anywhere else.
                { id: '9b2d6a48-7e51-4c03-bf94-1d8c5f0a3e72', name: 'lab-runner',
                  description: 'Isolated lab segment', kind: 'remote', enabled: true,
                  credentialsMode: 'delegated', labels: 'lab', sealsCredentials: false, signsResults: false,
                  maxConcurrent: 1, hostname: 'runner-lab-07', platform: 'linux/arm64',
                  version: '1.2.1', contractVersion: '2', lastSeenAt: '2026-09-18T10:41:00Z',
                  online: false, runningScans: 0 }
            ]);
            await enterApp(page, locale);
            await openScreen(page, '/agents');

            // **Scrolled to the table, because the page's argument is the row.** The queue and the
            // four tiles fill the first screenful, and the documentation's section on this page is
            // about what a row says — the credentials mode, whether results are attested, an agent
            // that has never announced. A capture that stopped at the fold would illustrate the
            // paragraph above it and none of the ones it is attached to.
            await page.getByText('lab-runner').first().scrollIntoViewIfNeeded();

            await expect(page.getByText('lab-runner').first()).toBeVisible({ timeout: 15_000 });
            await shoot(page, 'agents', locale);
        });
    });
