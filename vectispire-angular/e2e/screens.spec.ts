import { expect, test, type Page } from '@playwright/test';
import openapi from '../openapi.json';
import { asSchema, asSchemaList } from '../src/app/core/testing/contract';

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
/**
 * A JSON response for a route, checked against what the control plane publishes for that route.
 *
 * <p><b>Every stub, not only the ones somebody remembered to wrap.</b> `asSchema` existed and was
 * used for one floor; the fixtures beside it went on describing a server that had moved. The attack
 * path graph was captured with an empty "exploitable critical paths" tile and a risk score reading
 * "/ 100", because its stub predates `criticalExploitablePaths`, `riskScore` and `totalPaths` and
 * still spelt `isCriticalPath` as `isCritical`; the statement of applicability showed a framework
 * button with no name, its `title` never sent; the issue list read "seen undefined×". Nothing threw,
 * and every one of them was a fixture written from memory.
 *
 * <p>So the schema is looked up from the request itself — its method and path, matched against
 * `openapi.json` — rather than named at each call, which is the step that was forgotten. A problem
 * is collected, not thrown: an exception inside a route handler leaves the request pending and
 * surfaces as a timeout somewhere else, while `shoot` can refuse the capture and say why.
 */
async function stub(page: Page, pattern: string, body: unknown): Promise<void> {
    await page.route(pattern, (route) => {
        contractProblems.push(...againstContract(route.request().method(), new URL(route.request().url()).pathname, body));
        return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) });
    });
}

interface PublishedSchema { $ref?: string; type?: string; items?: PublishedSchema }
type Operations = Record<string, { responses?: Record<string, { content?: Record<string, { schema?: PublishedSchema }> }> }>;
const PUBLISHED = (openapi as unknown as { paths: Record<string, Operations> }).paths;

/** What the stub's body gets wrong about the route it answers; empty when nothing. */
function againstContract(method: string, path: string, body: unknown): string[] {
    // A literal segment before a template: `/rule-sets/coverage` is not `/rule-sets/{id}`.
    const route = Object.keys(PUBLISHED)
        .sort((a, b) => (a.match(/\{/g) ?? []).length - (b.match(/\{/g) ?? []).length)
        .find((template) => new RegExp(`^${template.replace(/\{[^}]+\}/g, '[^/]+')}$`).test(path));
    const content = route ? PUBLISHED[route][method.toLowerCase()]?.responses?.['200']?.content : undefined;
    if (!content) return [`${method} ${path}: the document publishes no such route, so nothing can check its stub`];
    const schema = Object.values(content)[0]?.schema;
    const name = (ref?: string) => ref?.split('/').pop() as Parameters<typeof asSchema>[0];
    try {
        if (schema?.$ref) asSchema(name(schema.$ref), body);
        else if (schema?.type === 'array' && schema.items?.$ref) asSchemaList(name(schema.items.$ref), body as unknown[]);
        return [];
    } catch (problem) {
        return [`${method} ${path}: ${(problem as Error).message.split('\n\n')[0]}`];
    }
}

/** What the stubs answered against the contract during the current case. */
const contractProblems: string[] = [];

/**
 * What the catch-all answered during the current case, by path.
 *
 * <p>Module state rather than a fixture: `stubEverything` is the only writer, `beforeEach` resets
 * it, and the cases run one at a time (`workers: 1`), so one array is one case.
 */
const fellThrough: string[] = [];

/**
 * The requests the catch-all may answer, because its answer is the true one for the capture.
 *
 * <p><b>Anything else a screen asks for has to be stubbed by name.</b> The dashboard was captured
 * for weeks reading "undefined person-days" and "undefined% (undefined resolved / undefined
 * opened)": it asks for the remediation debt, the posture analytics and the portfolio, nobody had
 * stubbed them, and `{}` rendered as words. The audit log's capture showed "undefined entries are
 * missing from this database" in red, on the page that exists to prove the log intact, because
 * `/audit-log/verify` fell through the same way. Neither threw, so the page-error guard below saw
 * nothing; an interpolated `undefined` renders as an empty string as often as a word, which is why
 * a text check alone would not be enough either.
 *
 * <p>Each entry is a request a screen makes for a form or a dialog the capture never opens, where
 * an empty answer reads exactly as "none". Adding one is a claim about what the picture shows; a
 * request missing from this list fails the capture and names itself.
 */
const FLOOR_IS_THE_ANSWER: readonly RegExp[] = [
    // Target pickers in a filter or a form: the screen's own data is stubbed by the case.
    /^\/api\/v1\/(repositories|containers)$/,
    // The repository form's credentials.
    /^\/api\/v1\/(ssh-keys|git-tokens)$/,
    // A form's defaults (the schedule's default interval, the visibility setting of the grant
    // dialog): read only once a form opens.
    /^\/api\/v1\/settings$/,
    // The access dialogs of the users and teams screens: the targets, the solution tree and the
    // accounts a grant or a membership can name.
    /^\/api\/v1\/(api-keys\/targets|solutions|users)$/,
    // The advisor is offered only when a model is configured; `{}` is "not configured", which is
    // what the captures should show, since no model runs behind them.
    /^\/api\/v1\/ai-advisor\/status$/
];

/**
 * Everything the shell asks for before any screen does, and a floor under the rest.
 *
 * <p>The catch-all matters more than it looks: a screen that fires one request nobody anticipated
 * would otherwise hang on a pending promise and be captured half-rendered. Answering `[]` or `{}`
 * by shape keeps it whole, and the per-screen stubs below override it. It is a floor and not an
 * answer: what it serves is recorded, and `shoot` refuses a capture that relied on it for anything
 * outside {@link FLOOR_IS_THE_ANSWER}.
 */
async function stubEverything(page: Page): Promise<void> {
    // **The catch-all goes first, and that order is the whole trick.** Playwright matches the most
    // recently registered route, so a general pattern added last would swallow every specific stub
    // below it and serve `{}` to screens that need data.
    await page.route('**/api/v1/**', (route) => {
        const url = route.request().url();
        fellThrough.push(new URL(url).pathname);
        // **A collection answered as an object breaks the page before it renders.** `ssh-keys` was
        // missing from this list, so the repositories screen — which loads them for its form —
        // received `{}`, and the table never appeared while the heading did. The fixture was not
        // at fault; this line was.
        const list = /\/(repositories|containers|issues|agents|teams|users|scans|rule-sets|ssh-keys|git-tokens|api-keys|gate-policies|notifications|exceptions|verdicts|keys)(\?|\/|$)/.test(url);
        return route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: list ? '[]' : '{}'
        });
    });

    // **Sign-in lands on the dashboard, so every capture passes through it.** Answered `{}` by the
    // catch-all, it threw on `posture.failingCount` in all of them. Checked against the published
    // schema so this floor cannot drift from the server the way the `{}` did; the tests that
    // photograph the dashboard register their own, richer answer after this one.
    await stub(
        page,
        '**/api/v1/dashboard',
        asSchema('DashboardOverview', {
            posture: {
                totalCount: 14,
                failingCount: 4,
                kevCount: 2,
                overdueCount: 5,
                neverScannedCount: 1,
                lastScanFailedCount: 1
            },
            backlogBySeverity: { CRITICAL: 4, HIGH: 12, MEDIUM: 31, LOW: 365 },
            qualityTotal: 0,
            failing: [],
            recentScans: []
        })
    );
    // The same page draws its trend from `points`, which the client claims is always sent; `{}`
    // threw on `points.length` as soon as the overview stopped throwing first.
    await stub(
        page,
        '**/api/v1/dashboard/trends*',
        asSchema('Trends', { points: [], mean_days_to_resolve: null, resolved_in_window: 0 })
    );
    // The three other panels of the same page, which every capture also lands on. An estate with
    // nothing measured: zeros and nulls the contract allows, not `{}`, which the debt card printed
    // as "undefined person-days" and the velocity line as "undefined% (undefined resolved …)".
    await stub(
        page,
        '**/api/v1/remediation/debt*',
        asSchema('SecurityDebtReport', {
            totalOpenIssues: 0, criticalIssues: 0, highIssues: 0, mediumIssues: 0, lowIssues: 0,
            totalEstimatedHours: 0, totalEstimatedPersonDays: 0,
            vulnerabilitiesDebtHours: 0, secretsDebtHours: 0, sastDebtHours: 0,
            iacDebtHours: 0, licenseDebtHours: 0, eolDebtHours: 0, topHighImpactFixes: []
        })
    );
    await stub(
        page,
        '**/api/v1/dashboard/posture-analytics*',
        asSchema('PostureTrendAnalytics', {
            windowDays: 90, overallMttrDays: null, mttrBySeverity: {},
            totalOpenedInWindow: 0, totalResolvedInWindow: 0, netResolutionRatePercentage: 0,
            dailySeries: [], targetScoreboard: []
        })
    );
    await stub(
        page,
        '**/api/v1/scorecards/global',
        asSchema('PortfolioScorecard', {
            totalTargets: 0, observedTargets: 0, grades: [], weakestTarget: null,
            openCriticalCount: 0, openHighCount: 0, openKevCount: 0, overdueCount: 0,
            licenseViolationCount: 0, riskPoints: 0
        })
    );
    // Password only: `configured` is whether an identity provider is wired at all, and none is.
    await stub(page, '**/api/v1/auth/methods',
               { configured: false, label: null, password: true, brandName: null, gitlabUrl: null });
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

    expect(contractProblems, 'stubs that disagree with the published contract').toEqual([]);

    // **Nothing the capture shows came from the floor.** See `FLOOR_IS_THE_ANSWER`: a request
    // answered by the catch-all and not listed there is data the screen renders from `{}`.
    const unstubbed = [...new Set(fellThrough)].filter((path) => !FLOOR_IS_THE_ANSWER.some((ok) => ok.test(path)));
    expect(unstubbed, 'requests the screen made that only the catch-all answered — stub them').toEqual([]);

    // **And nothing on the page reads as a value that was never sent.** The check above sees the
    // requests; this one sees a field missing from a stub that does exist, which renders the same
    // words. Whole words only, so "undefinedness" or a name containing "nan" do not trip it; the
    // rendered text (`innerText`, which includes what is scrolled out of view) and the attributes a
    // reader or a screen reader is given, since an accessible name built from `undefined` is as
    // wrong as a visible one.
    const leaks = await page.evaluate(() => {
        const unsent = /\b(undefined|NaN)\b|\[object Object\]/;
        const found = document.body.innerText.split('\n').filter((line) => unsent.test(line));
        for (const element of Array.from(document.body.querySelectorAll('[aria-label], [title], [alt], [placeholder]'))) {
            for (const attribute of ['aria-label', 'title', 'alt', 'placeholder']) {
                const value = element.getAttribute(attribute);
                if (value && unsent.test(value)) found.push(`${attribute}="${value}"`);
            }
        }
        return found;
    });
    expect(leaks, 'text rendered from a value the stub never sent').toEqual([]);

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

/**
 * The chain's verification, as the audit log and the attestation both show it.
 *
 * <p>One value for both screens, since they describe one log. `unverifiable` counts entries written
 * before chaining existed: history, not tampering, which is why the chain still reads intact.
 */
const AUDIT_CHAIN = {
    intact: true, broken: null, total: 1284, verified: 1240, unverifiable: 44,
    mirrored: true, missingFromMirror: 0, missingFromTable: 0
};

/**
 * The rule coverage of the estate these captures describe: rules for Java and Python, none for the
 * TypeScript it also holds. Every screen that carries the coverage banner is given the same answer,
 * so the banner is either on all of them or on none — the code quality capture shows it, so the
 * security overview and the repositories show it too.
 */
const RULE_COVERAGE = {
    state: 'PARTIAL', ruleFiles: 12,
    languagesWithRules: ['java', 'python'],
    ecosystemsInEstate: ['java', 'python', 'typescript'],
    uncovered: ['typescript']
};

/**
 * The upgrade the remediation plan leads with, and the dashboard's high-impact fix: the same action
 * on both captures. Log4Shell is helios-portal's, as on the issues, EPSS and attack path captures.
 */
const LOG4J_UPGRADE = {
    packageName: 'log4j-core', currentVersion: '2.14.1', recommendedVersion: '2.17.1',
    cveCountResolved: 12, criticalCveCount: 4, highCveCount: 8,
    estimatedHours: 1.3, leverageScore: 9.2,
    affectedCves: ['CVE-2021-44228'], affectedTargetNames: ['helios-portal']
};

/**
 * The estate's security debt, as the dashboard and the remediation plan both show it. 412 open by
 * the overview's severities (4, 12, 31, 365); the hours by family add up to the total, and the
 * person-days are the total over eight hours, rounded to one place as `SecurityDebtService` rounds
 * them. Secrets carry nearly all of it — the plan's "four hundred findings no upgrade closes".
 */
const SECURITY_DEBT = {
    totalOpenIssues: 412, criticalIssues: 4, highIssues: 12, mediumIssues: 31, lowIssues: 365,
    totalEstimatedHours: 812.3, totalEstimatedPersonDays: 101.5,
    vulnerabilitiesDebtHours: 12.3, secretsDebtHours: 798, sastDebtHours: 0,
    iacDebtHours: 2, licenseDebtHours: 0, eolDebtHours: 0
};

/**
 * The violations a target nobody examined fails with — `PolicyGate`'s `observation` rule, worded as
 * `Observation.refusal` words it. No issue, package or severity: the refusal is about the absence of
 * an examination, not about a finding.
 */
const NEVER_EXAMINED = {
    rule: 'observation', issueId: null, identifier: null, severity: null, package: null, fixVersions: null,
    reason: 'no scan of this target has completed — it was never examined, and an empty backlog is not a clean one'
};
const LAST_SCAN_FAILED = {
    ...NEVER_EXAMINED,
    reason: 'the last scan of this target failed — its backlog is not an observation of the code as it is'
};

test.describe('documentation screenshots', () => {
    // **A screen that throws can still be photographed, and was.** Sign-in lands on `/dashboard`,
    // and while the catch-all answered it `{}` every test logged `TypeError … 'failingCount'` from a
    // dashboard reading `posture` off nothing — in the browser console, which no assertion reads,
    // so every green run carried it. A page error now fails the capture it happened in, so a stub
    // that drifts from the contract cannot hide behind a picture that looks right.
    //
    // **`pageerror` alone would not have seen it.** A template that throws is caught by Angular's
    // `ErrorHandler`, which logs it through `console.error` and lets the page live on: the event
    // never fires. The first version of this guard listened to `pageerror` only and passed fifty
    // runs with the defect still in them. Both channels are collected.
    let pageErrors: string[] = [];
    test.beforeEach(({ page }) => {
        pageErrors = [];
        fellThrough.length = 0;
        contractProblems.length = 0;
        page.on('pageerror', (error) => pageErrors.push(error.message));
        page.on('console', (message) => {
            if (message.type() === 'error') pageErrors.push(message.text());
        });
    });
    test.afterEach(() => {
        expect(pageErrors, 'errors the page raised or logged').toEqual([]);
    });


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
            // The controls' names and the framework's title are the catalogue's
            // (`ComplianceFramework.ISO_27001`): the screen prints them, and a fixture that sent
            // neither photographed a framework button with nothing on it but its finding count.
            const line = (id: string, name: string, requirement: string, category: string,
                          measured: string, divergence: string) => ({
                control: { id, name, requirement, category },
                declaration: {
                    framework: 'ISO_27001', controlId: id, applicability: 'APPLICABLE',
                    justification: 'In scope.', implementation: 'IMPLEMENTED',
                    evidenceSource: 'VECTISPIRE', externalEvidence: null,
                    owner: 'n.faure', decidedBy: 'c.moreau',
                    decidedAt: '2026-01-05T00:00:00Z', reviewedAt: '2026-06-05T00:00:00Z',
                    reviewDueAt: '2027-06-05T00:00:00Z'
                },
                measured, divergence, reviewOverdue: false
            });
            await stub(page, '**/api/v1/compliance/soa', [{
                framework: 'ISO_27001', title: 'ISO/IEC 27001:2022',
                total: 2, declared: 2, findings: 1, reviewsOverdue: 0, complete: true,
                lines: [
                    line('ISO-A.5.15', 'Access Control & Secrets Protection',
                         'Credentials, private keys, and API tokens must be strictly protected and never leaked in code.',
                         'SECRETS_MANAGEMENT', 'COMPLIANT', 'CONSISTENT'),
                    line('ISO-A.8.8', 'Management of Technical Vulnerabilities',
                         'Information about technical vulnerabilities must be obtained in a timely manner and evaluated.',
                         'VULNERABILITY_MANAGEMENT', 'NON_COMPLIANT', 'CONTRADICTED')
                ]
            }]);
            // `reviewsOverdue: 0` above, so the list of lapsed reviews is empty — said, not left to
            // the catch-all's `{}`.
            await stub(page, '**/api/v1/compliance/soa/reviews/overdue', []);
            await enterApp(page, locale);
            await openScreen(page, '/soa');

            await expect(page.getByText('ISO-A.8.8').first()).toBeVisible({ timeout: 15_000 });
            await shoot(page, 'statement-of-applicability', locale);
        });

        test('remediation plan', async ({ page }, testInfo) => {
            const locale = edition(testInfo.project.name);
            await stubEverything(page);
            await stub(page, '**/api/v1/remediation/high-impact-fixes*', [LOG4J_UPGRADE]);
            await stub(page, '**/api/v1/remediation/debt*', { ...SECURITY_DEBT, topHighImpactFixes: [] });
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
                averageFleetEpss: 0.07,
                breakdownByTier: { CRITICAL_ARMED: 3, HIGH_PROBABLE: 8, MEDIUM_THEORETICAL: 41, LOW_PROBABILITY: 360 },
                topPriorities: [
                    {
                        issueId: 41, identifier: 'CVE-2021-44228', title: 'Log4Shell',
                        severity: 'critical', cvssScore: 10.0, epssScore: 0.975, epssPercentile: 0.999,
                        isKev: true, targetName: 'helios-portal',
                        targetKind: 'REPOSITORY', priorityScore: 98, priorityTier: 'CRITICAL_ARMED',
                        recommendedAction: 'P0_KEV_24H'
                    },
                    {
                        issueId: 42, identifier: 'CVE-2024-1086', title: 'Kernel use-after-free',
                        severity: 'high', cvssScore: 7.8, epssScore: 0.41, epssPercentile: 0.97,
                        isKev: false, targetName: 'basalt-libs',
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
                { id: 5, name: 'helios-portal', url: 'ssh://git@example.invalid/helios-portal.git', branch: 'main',
                  openIssues: 214, scanManualOnly: false }
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
            // **The picker has to be closed before the shot, not closing.** Its panel leaves on an
            // animation that `shoot` then switches off, which froze it open over the compare
            // button: both editions were captured with the target list still unfolded.
            await expect(page.getByRole('option')).toHaveCount(0, { timeout: 15_000 });

            // The two most recent are preselected, so the screen answers "since last time" before
            // anybody clicks. A capture of two empty pickers would be a capture of the old defect.
            await expect(page.getByText('#34').first()).toBeVisible({ timeout: 15_000 });
            await shoot(page, 'sbom-comparison', locale);
        });

        test('dashboard', async ({ page }, testInfo) => {
            const locale = edition(testInfo.project.name);
            await stubEverything(page);
            // **Every panel of the page, from one estate.** Fourteen targets, thirteen of them
            // scanned; 412 open findings, 4 critical, 12 high, 31 medium, 365 low; two exploited;
            // five past their deadline. The debt, the portfolio and the scoreboard below restate
            // those figures rather than invent their own — a dashboard whose cards disagree with
            // each other is a capture of a defect, whatever each card says on its own.
            await stub(page, '**/api/v1/dashboard', asSchema('DashboardOverview', {
                posture: { totalCount: 14, failingCount: 4, kevCount: 2, overdueCount: 5,
                           neverScannedCount: 1, lastScanFailedCount: 1 },
                backlogBySeverity: { CRITICAL: 4, HIGH: 12, MEDIUM: 31, LOW: 365 },
                qualityTotal: 1432,
                failing: [
                    { kind: 'repository', targetId: 5, name: 'helios-portal', observed: true, violations: [] },
                    { kind: 'container', targetId: 3, name: 'registry.example/api:1.4', observed: true, violations: [] },
                    // Failing because nobody examined them — the never-scanned and the last-failed
                    // tiles above — and tagged so, never as a severity.
                    { kind: 'repository', targetId: 6, name: 'basalt-libs', observed: false,
                      violations: [LAST_SCAN_FAILED] },
                    { kind: 'repository', targetId: 7, name: 'billing-legacy', observed: false,
                      violations: [NEVER_EXAMINED] }
                ],
                recentScans: [
                    { id: 34, status: 'completed', targetKind: 'repository', targetName: 'helios-portal',
                      repoId: 5, containerId: null, error: null, createdAt: '2026-09-17T21:04:00Z',
                      findingsCount: 7 },
                    { id: 33, status: 'failed', targetKind: 'repository', targetName: 'basalt-libs',
                      repoId: 6, containerId: null, error: 'clone refused', createdAt: '2026-09-17T03:10:00Z',
                      findingsCount: 0 }
                ]
            }));
            // Two charts rather than two axes: the backlog and the daily movements differ by two
            // orders of magnitude, so the capture has to show both curves readable.
            const days = [
                { day: '2026-09-12', open: 402, opened: 9, resolved: 2 },
                { day: '2026-09-13', open: 405, opened: 5, resolved: 2 },
                { day: '2026-09-14', open: 399, opened: 1, resolved: 7 },
                { day: '2026-09-15', open: 404, opened: 8, resolved: 3 },
                { day: '2026-09-16', open: 410, opened: 9, resolved: 3 },
                { day: '2026-09-17', open: 412, opened: 6, resolved: 4 }
            ];
            await stub(page, '**/api/v1/dashboard/trends*', asSchema('Trends', {
                points: days, mean_days_to_resolve: 11.4, resolved_in_window: 21
            }));
            // **The panel that read "undefined% (undefined resolved / undefined opened)".** The same
            // six days: 38 opened, 21 resolved, so the velocity is 21 / 38 = 55.3 %, rounded to one
            // place as `PostureTrendAnalytics` rounds it, and the overall time to fix is the
            // trend's mean. Below 80 %, which the screen colours amber: a backlog still growing.
            await stub(page, '**/api/v1/dashboard/posture-analytics*', asSchema('PostureTrendAnalytics', {
                windowDays: 90,
                overallMttrDays: 11.4,
                mttrBySeverity: { CRITICAL: 3.2, HIGH: 6.8, MEDIUM: 12.5, LOW: 19.0 },
                totalOpenedInWindow: 38,
                totalResolvedInWindow: 21,
                netResolutionRatePercentage: 55.3,
                dailySeries: days.map((point) => ({
                    date: point.day, openBacklog: point.open, newlyDiscovered: point.opened,
                    newlyResolved: point.resolved, rollingMttrDays: null
                })),
                // Ordered weakest first, as the server ranks it; the never-scanned target has no
                // grade and no score rather than a measured zero.
                targetScoreboard: [
                    { targetId: 5, targetName: 'helios-portal', targetKind: 'repository',
                      maturityGrade: 'F', securityScore: 18, riskPoints: 412.5,
                      openCritical: 3, openHigh: 7, openMedium: 18, openLow: 186,
                      totalResolved: 12, targetMttrDays: 9.6 },
                    { targetId: 3, targetName: 'registry.example/api', targetKind: 'container',
                      maturityGrade: 'D', securityScore: 44, riskPoints: 151.0,
                      openCritical: 1, openHigh: 3, openMedium: 8, openLow: 46,
                      totalResolved: 6, targetMttrDays: 14.2 },
                    { targetId: 6, targetName: 'basalt-libs', targetKind: 'repository',
                      maturityGrade: 'B', securityScore: 81, riskPoints: 38.5,
                      openCritical: 0, openHigh: 2, openMedium: 5, openLow: 30,
                      totalResolved: 3, targetMttrDays: 12.9 },
                    { targetId: 7, targetName: 'billing-legacy', targetKind: 'repository',
                      maturityGrade: 'NO_DATA', securityScore: null, riskPoints: null,
                      openCritical: 0, openHigh: 0, openMedium: 0, openLow: 0,
                      totalResolved: 0, targetMttrDays: null }
                ]
            }));
            // **The card that read "undefined person-days".** The remediation plan's debt, since it
            // is the same estate: 412 findings by the overview's severities, the hours by family
            // adding up to the total, the person-days that total over eight hours as
            // `SecurityDebtService` rounds it, and the plan's one upgrade as the high-impact fix.
            await stub(page, '**/api/v1/remediation/debt*',
                       asSchema('SecurityDebtReport', { ...SECURITY_DEBT, topHighImpactFixes: [LOG4J_UPGRADE] }));
            // Fourteen targets by grade, `NO_DATA` the one never scanned; the open counts are the
            // overview's, and the weakest is the scoreboard's first row.
            await stub(page, '**/api/v1/scorecards/global', asSchema('PortfolioScorecard', {
                totalTargets: 14, observedTargets: 13,
                grades: [
                    { grade: 'A_PLUS', targets: 1 }, { grade: 'A', targets: 3 }, { grade: 'B', targets: 4 },
                    { grade: 'C', targets: 2 }, { grade: 'D', targets: 2 }, { grade: 'F', targets: 1 },
                    { grade: 'NO_DATA', targets: 1 }
                ],
                weakestTarget: { targetId: 5, targetKind: 'repository', targetName: 'helios-portal',
                                 grade: 'F', score: 18, riskPoints: 412.5 },
                openCriticalCount: 4, openHighCount: 12, openKevCount: 2, overdueCount: 5,
                licenseViolationCount: 3, riskPoints: 734.5
            }));
            await enterApp(page, locale);
            await openScreen(page, '/dashboard');

            await expect(page.getByText('helios-portal').first()).toBeVisible({ timeout: 15_000 });
            // The velocity line, by its figures: the same in both editions.
            await expect(page.getByText(/55\.3\s?%/).first()).toBeVisible({ timeout: 15_000 });
            await shoot(page, 'dashboard', locale);
        });

        test('issues', async ({ page }, testInfo) => {
            const locale = edition(testInfo.project.name);
            await stubEverything(page);
            const issue = (id: number, identifier: string, severity: string, pkg: string,
                           version: string, target: string, isKev: boolean, timesSeen: number,
                           where: { repoId: number } | { containerId: number }) => ({
                id, targetKind: 'repoId' in where ? 'repository' : 'container',
                type: 'vulnerability', state: 'open', isKev, timesSeen,
                firstSeenAt: '2026-08-21T07:57:53Z', lastSeenAt: '2026-09-17T21:04:00Z',
                triageStatus: 'under_review', repoId: null, containerId: null, ...where, targetName: target,
                identifier, severity, packageName: pkg, packageVersion: version,
                purl: `pkg:maven/${pkg}@${version}`, filePath: null, line: null
            });
            await stub(page, '**/api/v1/issues*', {
                items: [
                    // Log4Shell is in the KEV catalogue, as on the EPSS capture; the other two are not.
                    issue(41, 'CVE-2021-44228', 'critical', 'log4j-core', '2.14.1', 'helios-portal', true, 14, { repoId: 5 }),
                    issue(42, 'CVE-2024-1086', 'high', 'linux-libc-dev', '6.1.0', 'registry.example/api:1.4', false, 6, { containerId: 3 }),
                    issue(43, 'CVE-2023-44487', 'medium', 'netty-codec-http2', '4.1.94', 'basalt-libs', false, 9, { repoId: 6 })
                ],
                total: 412, limit: 50, offset: 0
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
                  displayName: 'helios-portal', name: 'helios-portal', subPath: null,
                  openIssues: 214, scanManualOnly: false }
            ]);
            // Node notes and the scenario are tokens since this week: the graph and its narrative
            // are written by the screen, so the two editions differ throughout.
            const graph = {
                // One chain, critical and reachable from outside: the tiles above the graph count it.
                targetId: 5, targetName: 'helios-portal',
                totalPaths: 1, criticalExploitablePaths: 1, riskScore: 92,
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
                    { id: 'e1', source: 'ingress', target: 'ep-1', label: 'REACHES', isCriticalPath: true },
                    { id: 'e2', source: 'ep-1', target: 'vuln-1', label: 'INVOKES', isCriticalPath: true },
                    { id: 'e3', source: 'vuln-1', target: 'db', label: 'EXFILTRATES_DATA', isCriticalPath: true }
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
                  openIssues: 214, tier: 'TIER_1_MISSION_CRITICAL', scanIntervalMinutes: 1440, scanCron: null, scanManualOnly: false,
                  schedule: { mode: 'interval', intervalMinutes: 1440 },
                  sshKeyId: null, requiredAgentLabel: null, lastScheduledScanAt: '2026-09-17T21:00:00Z',
                  lastScan: { id: 34, status: 'completed', createdAt: '2026-09-17T21:04:00Z', error: null } },
                { id: 6, url: 'ssh://git@example.invalid/basalt-libs.git', branch: 'master',
                  displayName: 'basalt-libs', name: 'basalt-libs', subPath: null,
                  openIssues: 37, tier: 'TIER_3_INTERNAL', scanIntervalMinutes: null, scanCron: '0 3 * * *', scanManualOnly: false,
                  schedule: { mode: 'cron', intervalMinutes: null },
                  sshKeyId: null, requiredAgentLabel: null, lastScheduledScanAt: '2026-09-16T03:00:00Z',
                  lastScan: { id: 30, status: 'failed', createdAt: '2026-09-16T03:11:00Z',
                              error: 'clone refused' } }
            ]);
            await stub(page, '**/api/v1/rule-sets/coverage', RULE_COVERAGE);
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
                  scanIntervalMinutes: 720, scanCron: null, requiredAgentLabel: null, scanManualOnly: false,
                  schedule: { mode: 'interval', intervalMinutes: 720 },
                  lastScheduledScanAt: '2026-09-17T18:00:00Z',
                  lastScan: { id: 32, status: 'completed', createdAt: '2026-09-17T18:06:00Z', error: null } },
                { id: 4, imageName: 'registry.example/nginx-edge', tag: 'sha256:9f2c1d4b7a03e85f6c2b9d10a47e3f8521bc60d9e7a4f31682c5b0ad9e14f7c3',
                  reference: 'registry.example/nginx-edge@sha256:9f2c1d4b7a03e85f6c2b9d10a47e3f8521bc60d9e7a4f31682c5b0ad9e14f7c3',
                  registry: 'registry.example', openIssues: 0, tier: 'TIER_2_BUSINESS_OPERATIONAL',
                  scanIntervalMinutes: null, scanCron: '0 4 * * *', requiredAgentLabel: 'dmz', scanManualOnly: false,
                  schedule: { mode: 'cron', intervalMinutes: null },
                  lastScheduledScanAt: '2026-09-18T04:00:00Z',
                  lastScan: { id: 35, status: 'completed', createdAt: '2026-09-18T04:03:00Z', error: null } },
                { id: 5, imageName: 'registry.example/batch-runner', tag: '2026.09',
                  reference: 'registry.example/batch-runner:2026.09', registry: 'registry.example',
                  openIssues: 12, tier: 'TIER_3_INTERNAL',
                  scanIntervalMinutes: null, scanCron: null, requiredAgentLabel: null, scanManualOnly: false,
                  schedule: { mode: 'default', intervalMinutes: 10080 },
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
            await stub(page, '**/api/v1/rule-sets/coverage', RULE_COVERAGE);
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
                posture: { totalCount: 14, failingCount: 4, kevCount: 2, overdueCount: 5,
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
                      fail_on_uncovered_languages: false, include_plugins: false,
                      note: 'criticals in transitive dependencies were failing every build and teams had started bypassing the gate',
                      created_by: 'c.moreau', created_at: '2026-08-02T09:12:00Z' },
                    { kind: 'repository', target_id: 5, target_name: 'helios-portal', version: 2,
                      fail_on_severity: 'medium', fail_on_kev: true, fixable_only: false,
                      include_triaged: false, include_ai_review: false,
                      fail_on_uncovered_languages: false, include_plugins: false,
                      note: 'Tier 1 payment path, held above the estate bar for the quarter',
                      created_by: 'c.moreau', created_at: '2026-09-04T16:40:00Z' }
                ],
                built_in: { kind: 'built-in', target_id: null, target_name: null, version: 0,
                            fail_on_severity: 'high', fail_on_kev: true, fixable_only: false,
                            include_triaged: false, include_ai_review: false,
                            fail_on_uncovered_languages: false, include_plugins: false, note: null,
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
            // failed. **Both fail**, with an `observation` violation and nothing else: their backlog
            // is empty or stale, and the gate refuses a target nobody examined rather than passing
            // it on an empty list (`Observation.refusal`). They were captured "Passing" until the
            // gate stopped failing open — beside a banner saying the gate refuses them.
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
                totalCount: 4, failingCount: 3, kevCount: 1,
                neverScannedCount: 1, lastScanFailedCount: 1,
                targets: [
                    { targetId: 5, kind: 'repository', name: 'helios-portal', observed: true,
                      passed: false, lastScanAt: '2026-09-17T21:04:00Z', lastScanId: 34,
                      observation: 'ok',
                      policy: { source: 'built-in', version: null },
                      verdict: { passed: false, evaluated: 412, violations: [],
                                 countsBySeverity: { CRITICAL: 1, HIGH: 3 } } },
                    { targetId: 6, kind: 'repository', name: 'basalt-libs', observed: false,
                      passed: false, lastScanAt: '2026-09-16T03:11:00Z', lastScanId: 30,
                      observation: 'last_scan_failed',
                      policy: { source: 'built-in', version: null },
                      verdict: { passed: false, evaluated: 37, violations: [LAST_SCAN_FAILED],
                                 countsBySeverity: {} } },
                    // An empty backlog, which would satisfy every policy: the whole reason the
                    // observation column exists, and the reason the gate no longer reads it alone.
                    { targetId: 7, kind: 'repository', name: 'billing-legacy', observed: false,
                      passed: false, lastScanAt: null, lastScanId: null,
                      observation: 'never_scanned',
                      policy: { source: 'built-in', version: null },
                      verdict: { passed: false, evaluated: 0, violations: [NEVER_EXAMINED],
                                 countsBySeverity: {} } }
                ]
            });
            await stub(page, '**/api/v1/rule-sets/coverage', RULE_COVERAGE);
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
            //
            // **`passed` and `refused` count this page, not the register** (`VerdictRegister`):
            // the fixture used to claim 128 and 6 above two rows, and the screen — which computes
            // its rate from the rows — printed "6 refusals" beside a 50 % rate. And `target_kind` is
            // `REPOSITORY` or `CONTAINER`, as `GateController` writes it: the lowercase spelling
            // matched neither, and every repository was captured as an image.
            //
            // The never-scanned target is refused on zero examined issues, its one violation the
            // `observation` rule; the clean image passes on zero, which the footnote calls out.
            const verdict = (id: string, kind: string, targetId: number, passed: boolean, evaluated: number,
                             violations: number, counts: Record<string, number>, decidedAt: string) => ({
                id: `0195f3a1-8a2b-7c4d-9e1f-${id}`, target_kind: kind, target_id: targetId,
                passed, evaluated, violations, fail_on_severity: 'high',
                policy_source: 'built-in', policy_version: null, relaxations_ignored: false,
                counts_by_severity: counts, decided_at: decidedAt, decided_by: 'ci'
            });
            await stub(page, '**/api/v1/gate/verdicts*', {
                passed: 2, refused: 3, next_cursor: null,
                verdicts: [
                    verdict('2a3b4c5d6e81', 'CONTAINER', 4, true, 0, 0, {}, '2026-09-18T04:04:00Z'),
                    verdict('2a3b4c5d6e7f', 'REPOSITORY', 5, false, 412, 4, { CRITICAL: 1, HIGH: 3 },
                            '2026-09-17T21:05:00Z'),
                    verdict('2a3b4c5d6e82', 'CONTAINER', 3, false, 58, 2, { CRITICAL: 1, HIGH: 1 },
                            '2026-09-17T18:07:00Z'),
                    verdict('2a3b4c5d6e83', 'REPOSITORY', 7, false, 0, 1, {}, '2026-09-17T09:30:00Z'),
                    // Before its last scan failed on the 16th: after it, the gate refuses it too.
                    verdict('2a3b4c5d6e80', 'REPOSITORY', 6, true, 37, 0, {}, '2026-09-15T03:12:00Z')
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
            // **The verification leads the page, and it fell through to the catch-all.** `{}` has
            // no `intact`, so the screen took the broken branch and printed "undefined entries are
            // missing from this database" in red — on the capture meant to show a log that proves
            // itself intact.
            await stub(page, '**/api/v1/audit-log/verify', AUDIT_CHAIN);
            await stub(page, '**/api/v1/audit-log/operation-types',
                       ['GATE_EVALUATED', 'SETTING_CHANGED', 'TRIAGE_DECIDED']);
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
            await stub(page, '**/api/v1/audit-log/verify', AUDIT_CHAIN);
            await stub(page, '**/api/v1/compliance/summary*', {
                totalMonitoredTargets: 14, observedTargets: 12, freshTargets: 11,
                passingGateTargets: 10, overdueCount: 5, dueSoonCount: 2,
                mttr: null, targets: [],
                // **The six frameworks, which the capture showed as "compliance could not be
                // read".** `evaluations: []` is what the screen receives when nothing could be
                // evaluated, and it says so — an error state photographed as the page's normal
                // look. ISO 27001 at 71 is the compliance progress capture's last month.
                evaluations: [
                    { framework: 'NIS_2', overallStatus: 'PARTIAL', scorePercentage: 68, controls: [] },
                    { framework: 'ISO_27001', overallStatus: 'PARTIAL', scorePercentage: 71, controls: [] },
                    { framework: 'EU_CRA', overallStatus: 'PARTIAL', scorePercentage: 62, controls: [] },
                    { framework: 'DORA', overallStatus: 'PARTIAL', scorePercentage: 74, controls: [] },
                    { framework: 'PCI_DSS', overallStatus: 'NON_COMPLIANT', scorePercentage: 45, controls: [] },
                    { framework: 'SOC_2', overallStatus: 'PARTIAL', scorePercentage: 77, controls: [] }
                ]
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
            // No scan waits for credentials an agent keeps: the unroutable notice above is this
            // page's one warning, and a second would bury it.
            await stub(page, '**/api/v1/admin/agents/credentialed-backlog', { scans: 0, labels: [], keptAgents: [] });
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

        test('rule sets', async ({ page }, testInfo) => {
            const locale = edition(testInfo.project.name);
            await stubEverything(page);
            await stub(page, '**/api/v1/rule-sets/coverage', RULE_COVERAGE);
            // An active set and a stored one, because the screen's two states only mean something
            // beside each other — and because the button this capture clicks exists on the stored
            // row alone.
            await stub(page, '**/api/v1/rule-sets', {
                ruleSets: [
                    { id: 4, name: 'opengrep-rules 2026.06', ruleCount: 1284, fileCount: 312,
                      contentHash: 'a91f3c7d5e28b0461d9c2f8a7b3e5061', sizeBytes: '4180224',
                      uploadedAt: '2026-06-11T10:24:00Z', uploadedBy: 'c.moreau',
                      isActive: true, activationNote: 'first estate-wide set' },
                    { id: 7, name: 'internal-java-rules', ruleCount: 96, fileCount: 18,
                      contentHash: '5c0b8e2a41f7d93620ae4c1b8f6d3057', sizeBytes: '294912',
                      uploadedAt: '2026-09-15T08:50:00Z', uploadedBy: 'c.moreau',
                      isActive: false, activationNote: null }
                ]
            });
            // **The panel this page exists for.** `removedRules` is large and `affectedIssues` is
            // not zero, which is the only combination that says what activation actually costs:
            // the rules that go are rules whose open issues resolve on the next scan, and their
            // justifications, review dates and decider go with them. A fixture where nothing is
            // lost would render the reassuring branch and photograph a confirmation dialog.
            await stub(page, '**/api/v1/rule-sets/*/impact', {
                addedRules: 96, removedRules: 1284, affectedIssues: 317,
                // Four rather than the dozen this would really return: the panel is already the
                // tallest thing on the page, and a monospace list that runs off the bottom of the
                // capture illustrates nothing that the first line has not already said.
                losingIssues: [
                    'java.lang.security.audit.formatted-sql-string',
                    'java.lang.security.audit.crypto.weak-hash',
                    'python.lang.correctness.unchecked-subprocess',
                    'java.lang.maintainability.dead-catch-block'
                ]
            });
            await enterApp(page, locale);
            await openScreen(page, '/rule-sets');

            // **Clicked rather than stubbed open.** The impact is fetched when the button is
            // pressed and never before — the whole reason this screen has two steps is that the
            // number it shows is invisible in the data and permanent in its effect. A capture that
            // arrived at the panel some other way would be illustrating a screen nobody can reach.
            await expect(page.getByText('internal-java-rules').first()).toBeVisible({ timeout: 15_000 });
            await page.getByRole('button', { name: /review activation|examiner l'activation/i }).first().click();
            await expect(page.getByText('317').first()).toBeVisible({ timeout: 15_000 });
            // **The foot of the panel, not the top of it.** `scrollIntoViewIfNeeded` on the
            // number stops as soon as its top edge is in view, which left the list of rules
            // losing issues running off the bottom of the capture; scrolling `window` instead
            // moved almost nothing, because the element that scrolls here is not `body`. Asking
            // the browser to bring the last card's end into view settles both.
            // **Anchored on the number, aligned to the top.** `scrollIntoViewIfNeeded` stops the
            // moment the element's top edge is in view, which left the list of rules losing issues
            // off the bottom; scrolling `window` moved almost nothing, because the element that
            // scrolls here is not `body`; and `block: 'end'` on the card missed, because the
            // `p-card` host measures 207px and does not enclose its projected content. Putting the
            // figure at the top of the viewport leaves the whole panel below it.
            await page.getByText('317').first().evaluate((node) =>
                node.scrollIntoView({ block: 'start', behavior: 'instant' }));

            await shoot(page, 'rule-sets', locale);
        });
    });
