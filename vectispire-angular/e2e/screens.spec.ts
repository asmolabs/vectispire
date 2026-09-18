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
                        isKev: true, reachability: 'REACHABLE', targetName: 'portail-client',
                        targetKind: 'REPOSITORY', priorityScore: 98, priorityTier: 'CRITICAL_ARMED',
                        recommendedAction: 'P0_KEV_24H'
                    },
                    {
                        issueId: 42, identifier: 'CVE-2024-1086', title: 'Kernel use-after-free',
                        severity: 'high', cvssScore: 7.8, epssScore: 0.41, epssPercentile: 0.97,
                        isKev: false, reachability: 'UNKNOWN', targetName: 'arm-libs',
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
                { id: 5, name: 'portail-client', url: 'ssh://git@example.invalid/portail.git', branch: 'main' }
            ]);
            // The history the two pickers read. It replaced two number fields asking for internal
            // identifiers, so a capture showing dates is the whole point of the change.
            await stub(page, '**/api/v1/scans*', [
                { id: 34, status: 'completed', branch: 'main', targetKind: 'REPOSITORY',
                  targetName: 'portail-client', createdAt: '2026-09-17T21:04:00Z', durationMs: 91_000,
                  findingsCount: 7, newIssuesCount: 1, resolvedIssuesCount: 3, error: null,
                  claimedBy: null, attempts: 1, targetId: 5 },
                { id: 33, status: 'completed', branch: 'main', targetKind: 'REPOSITORY',
                  targetName: 'portail-client', createdAt: '2026-09-10T21:03:00Z', durationMs: 88_000,
                  findingsCount: 9, newIssuesCount: 0, resolvedIssuesCount: 0, error: null,
                  claimedBy: null, attempts: 1, targetId: 5 }
            ]);
            await enterApp(page, locale);
            await openScreen(page, '/inventory');

            // The comparison is the second tab; by position, because the label is translated.
            await page.getByRole('button').filter({ hasText: /SBOM|diff|comparaison/i }).first().click();
            await page.locator('#diff-target').click();
            await page.getByRole('option').filter({ hasText: 'portail-client' }).first().click();

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
                    { kind: 'repository', targetId: 5, name: 'portail-client', violations: [] },
                    { kind: 'container', targetId: 3, name: 'registry.example/api:1.4', violations: [] }
                ],
                recentScans: [
                    { id: 34, status: 'completed', targetKind: 'repository', targetName: 'portail-client',
                      repoId: 5, containerId: null, error: null, createdAt: '2026-09-17T21:04:00Z' },
                    { id: 33, status: 'failed', targetKind: 'repository', targetName: 'arm-libs',
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

            await expect(page.getByText('portail-client').first()).toBeVisible({ timeout: 15_000 });
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
                    issue(41, 'CVE-2021-44228', 'critical', 'log4j-core', '2.14.1', 'portail-client'),
                    issue(42, 'CVE-2024-1086', 'high', 'linux-libc-dev', '6.1.0', 'registry.example/api:1.4'),
                    issue(43, 'CVE-2023-44487', 'medium', 'netty-codec-http2', '4.1.94', 'arm-libs')
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
                { id: 5, url: 'ssh://git@example.invalid/portail.git', branch: 'main',
                  displayName: 'portail-client', name: 'portail-client', subPath: null }
            ]);
            // Node notes and the scenario are tokens since this week: the graph and its narrative
            // are written by the screen, so the two editions differ throughout.
            const graph = {
                targetId: 5, targetName: 'portail-client',
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
                { id: 5, url: 'ssh://git@example.invalid/portail.git', branch: 'main',
                  displayName: 'portail-client', name: 'portail-client', subPath: null,
                  openIssues: 214, tier: 'TIER_1', scanIntervalMinutes: 1440, scanCron: null,
                  sshKeyId: null, requiredAgentLabel: null, lastScheduledScanAt: '2026-09-17T21:00:00Z',
                  lastScan: { id: 34, status: 'completed', createdAt: '2026-09-17T21:04:00Z', error: null } },
                { id: 6, url: 'ssh://git@example.invalid/arm-libs.git', branch: 'master',
                  displayName: 'arm-libs', name: 'arm-libs', subPath: null,
                  openIssues: 37, tier: 'TIER_3', scanIntervalMinutes: null, scanCron: '0 3 * * *',
                  sshKeyId: null, requiredAgentLabel: null, lastScheduledScanAt: '2026-09-16T03:00:00Z',
                  lastScan: { id: 30, status: 'failed', createdAt: '2026-09-16T03:11:00Z',
                              error: 'clone refused' } }
            ]);
            await enterApp(page, locale);
            await openScreen(page, '/repositories');

            await expect(page.getByText('arm-libs').first()).toBeVisible({ timeout: 15_000 });
            await shoot(page, 'repositories', locale);
        });

        test('security overview', async ({ page }, testInfo) => {
            const locale = edition(testInfo.project.name);
            await stubEverything(page);
            // The two cases no other screen names: a target never scanned, and one whose last scan
            // failed. Both are green everywhere else, which is the point of this page.
            await stub(page, '**/api/v1/security/overview*', {
                totalCount: 4, failingCount: 1, kevCount: 1,
                neverScannedCount: 1, lastScanFailedCount: 1,
                targets: [
                    { targetId: 5, kind: 'repository', name: 'portail-client', observed: true,
                      passed: false, lastScanAt: '2026-09-17T21:04:00Z', lastScanId: 34,
                      observation: 'FRESH',
                      policy: { source: 'built-in', version: null },
                      verdict: { passed: false, evaluated: 412, violations: [],
                                 countsBySeverity: { CRITICAL: 1, HIGH: 3 } } },
                    { targetId: 6, kind: 'repository', name: 'arm-libs', observed: true,
                      passed: true, lastScanAt: '2026-09-16T03:11:00Z', lastScanId: 30,
                      observation: 'STALE',
                      policy: { source: 'built-in', version: null },
                      verdict: { passed: true, evaluated: 37, violations: [], countsBySeverity: {} } },
                    { targetId: 7, kind: 'repository', name: 'billing-legacy', observed: false,
                      passed: true, lastScanAt: null, lastScanId: null,
                      observation: 'NEVER_SCANNED',
                      policy: { source: 'built-in', version: null }, verdict: null }
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
                      description: 'CVE-2021-44228 marked under review on portail-client',
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
    });
