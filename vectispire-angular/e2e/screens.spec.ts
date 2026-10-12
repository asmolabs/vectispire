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

/**
 * The same, for a path whose methods answer different things — the forge selection is read with a
 * GET and changed with a POST to one address, and `stub` would hand the POST the GET's page.
 *
 * <p>A method left out falls back to the routes registered before, the catch-all last, so it is
 * recorded there like any other request nobody stubbed.
 */
async function stubByMethod(page: Page, pattern: string, bodies: Partial<Record<string, unknown>>): Promise<void> {
    await page.route(pattern, (route) => {
        const method = route.request().method();
        if (!(method in bodies)) return route.fallback();
        const body = bodies[method];
        contractProblems.push(...againstContract(method, new URL(route.request().url()).pathname, body));
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
            backlogBySeverity: { critical: 4, high: 12, medium: 31, low: 365 },
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

/**
 * The violations the two observed failing targets carry — the gate verdicts capture's four for
 * helios-portal (one critical, three high) and two for the API image — worded as `PolicyGate` words
 * them. Log4Shell is the exploited one, so it fails on the KEV rule and not a second time on its
 * severity, as the gate reports it.
 */
const severityViolation = (issueId: number, identifier: string, severity: string, pkg: string, fixVersions: string) => ({
    rule: 'severity', issueId, identifier, severity, package: pkg, fixVersions,
    reason: `severity ${severity} >= threshold high`
});
const HELIOS_VIOLATIONS = [
    { rule: 'kev', issueId: 41, identifier: 'CVE-2021-44228', severity: 'critical', package: 'log4j-core',
      fixVersions: '2.17.1', reason: 'actively exploited vulnerability (CISA KEV catalog)' },
    severityViolation(44, 'CVE-2024-38816', 'high', 'spring-webmvc', '6.1.13'),
    severityViolation(45, 'CVE-2022-25857', 'high', 'snakeyaml', '1.31'),
    severityViolation(46, 'CVE-2024-47072', 'high', 'xstream', '1.4.21')
];
const API_IMAGE_VIOLATIONS = [
    severityViolation(47, 'CVE-2023-38545', 'critical', 'libcurl4', '7.88.1-10+deb12u4'),
    severityViolation(42, 'CVE-2024-1086', 'high', 'linux-libc-dev', '6.1.76-1')
];

/**
 * The dashboard's overview, which the scan detail capture also passes through: its recent scans are
 * the way a reader reaches a scan. Scan 34 is the SBOM comparison's newest — seven issues, one new,
 * three resolved — and the scan detail capture opens it.
 */
const DASHBOARD_OVERVIEW = {
    posture: { totalCount: 14, failingCount: 4, kevCount: 2, overdueCount: 5,
               neverScannedCount: 1, lastScanFailedCount: 1 },
    backlogBySeverity: { critical: 4, high: 12, medium: 31, low: 365 },
    qualityTotal: 1432,
    failing: [
        { kind: 'repository', targetId: 5, name: 'helios-portal', observed: true, violations: HELIOS_VIOLATIONS },
        { kind: 'container', targetId: 3, name: 'registry.example/api:1.4', observed: true,
          violations: API_IMAGE_VIOLATIONS },
        // Failing because nobody examined them — the never-scanned and the last-failed
        // tiles above — and tagged so, never as a severity.
        { kind: 'repository', targetId: 6, name: 'basalt-libs', observed: false,
          violations: [LAST_SCAN_FAILED] },
        { kind: 'repository', targetId: 7, name: 'billing-legacy', observed: false,
          violations: [NEVER_EXAMINED] }
    ],
    recentScans: [
        { id: 35, status: 'completed', targetKind: 'container', targetName: 'registry.example/nginx-edge',
          repoId: null, containerId: 4, error: null, createdAt: '2026-09-18T04:03:00Z', findingsCount: 0 },
        { id: 34, status: 'completed', targetKind: 'repository', targetName: 'helios-portal',
          repoId: 5, containerId: null, error: null, createdAt: '2026-09-17T21:04:00Z',
          findingsCount: 7 },
        { id: 32, status: 'completed', targetKind: 'container', targetName: 'registry.example/api:1.4',
          repoId: null, containerId: 3, error: null, createdAt: '2026-09-17T18:06:00Z', findingsCount: 58 },
        { id: 30, status: 'failed', targetKind: 'repository', targetName: 'basalt-libs',
          repoId: 6, containerId: null, error: 'clone refused', createdAt: '2026-09-16T03:11:00Z',
          findingsCount: 0 }
    ]
};

/** An `OpenIssues` tally, its total the sum of its severities as the server counts it. */
const openIssues = (critical: number, high: number, medium: number, low: number) => ({
    critical, high, medium, low, negligible: 0, unknown: 0, total: critical + high + medium + low
});

/**
 * The estate's solutions and projects, as `/solutions` answers them: the tree the solutions screen
 * draws, and the one the declared sources and the forge import read names from. Helios's figures
 * are the dashboard scoreboard's for its repository and its image; the two images nobody filed are
 * the containers capture's other two.
 */
const SOLUTION_TREE = {
    solutions: [
        {
            id: 1, name: 'Customer services', description: 'What customers reach directly',
            createdAt: '2026-05-04T09:00:00Z', partial: false, repositoryCount: 1, containerCount: 1,
            openIssues: openIssues(4, 10, 26, 232),
            projects: [
                { id: 11, solutionId: 1, name: 'Helios portal', description: 'The customer portal and its API image',
                  createdAt: '2026-05-04T09:05:00Z', partial: false, checklistsVisible: true,
                  repositoryCount: 1, containerCount: 1, openIssues: openIssues(4, 10, 26, 232),
                  repositories: [{ id: 5, name: 'helios-portal' }],
                  containers: [{ id: 3, name: 'registry.example/api:1.4' }],
                  detectedLanguages: ['java', 'typescript'], languagesUnknownFor: [] }
            ]
        },
        {
            id: 2, name: 'Platform', description: 'Shared code and back-office services',
            createdAt: '2026-05-04T09:10:00Z', partial: false, repositoryCount: 2, containerCount: 0,
            openIssues: openIssues(0, 2, 5, 30),
            projects: [
                { id: 12, solutionId: 2, name: 'Shared libraries', description: null,
                  createdAt: '2026-05-04T09:12:00Z', partial: false, checklistsVisible: false,
                  repositoryCount: 1, containerCount: 0, openIssues: openIssues(0, 2, 5, 30),
                  repositories: [{ id: 6, name: 'basalt-libs' }], containers: [],
                  detectedLanguages: ['java', 'python'], languagesUnknownFor: [] },
                // Never scanned, so nothing says what it is written in — said, not left blank.
                { id: 13, solutionId: 2, name: 'Billing', description: 'Invoicing, being rewritten',
                  createdAt: '2026-06-22T14:00:00Z', partial: false, checklistsVisible: false,
                  repositoryCount: 1, containerCount: 0, openIssues: openIssues(0, 0, 0, 0),
                  repositories: [{ id: 7, name: 'billing-legacy' }], containers: [],
                  detectedLanguages: [], languagesUnknownFor: [7] }
            ]
        }
    ],
    unfiled: {
        repositoryCount: 0, containerCount: 2, repositories: [],
        containers: [{ id: 4, name: 'registry.example/nginx-edge' }, { id: 5, name: 'registry.example/batch-runner:2026.09' }],
        openIssues: openIssues(0, 1, 4, 7)
    }
};

/**
 * The HTTPS clone tokens, one per forge host the estate clones from. The internal GitLab's is the
 * one the repository form and the forge import offer for `git.example.org`; the last is still
 * readable only under the previous encryption key, the state the column exists for.
 */
const GIT_TOKENS = [
    { id: '4d2b8e61-7c90-4f13-a5d2-9e0b3c6f1a74', name: 'gitlab-read', host: 'git.example.org',
      username: 'vectispire-bot', encryptionState: 'current', createdAt: '2026-08-03T10:15:00Z',
      usedByRepositories: 4 },
    { id: '91e7c3a0-2b5d-4e68-8f14-6a0d9c2b7e53', name: 'github-mirror-read', host: 'github.com',
      username: null, encryptionState: 'current', createdAt: '2026-07-21T08:40:00Z', usedByRepositories: 2 },
    { id: 'c6a4f2d9-8e17-4b30-9c5a-1d7e3b0f6a28', name: 'bitbucket-legacy-read', host: 'bitbucket.example.org',
      username: 'x-token-auth', encryptionState: 'previous_key', createdAt: '2026-02-11T15:05:00Z',
      usedByRepositories: 1 }
];

/**
 * A self-managed GitLab on the internal network behind the organisation's own CA — the estate
 * decision 0037 was written for — whose last discovery found three new repositories, one changed
 * and one gone since the one before.
 */
const FORGE_ID = '6f1c2a9e-0b7d-4c3e-9a51-3d2e8f40b7aa';
const FORGE_DISCOVERY = {
    id: 12, connectionId: FORGE_ID, state: 'completed', reason: null, detail: null, attempts: 1,
    namespacesSeen: 6, repositoriesSeen: 41, repositoriesSkipped: 0, requestsMade: 47,
    rateLimitWaitSeconds: 0, rateLimitResetAt: null, unreadableNamespaces: [],
    requestedAt: '2026-09-18T08:00:00Z', requestedBy: 'c.moreau',
    startedAt: '2026-09-18T08:00:02Z', finishedAt: '2026-09-18T08:01:10Z',
    newCount: 3, changedCount: 1, goneCount: 1
};
const FORGE_CONNECTION = {
    id: FORGE_ID, name: 'Internal GitLab', kind: 'gitlab', edition: 'gitlab_self_managed',
    baseUrl: 'https://git.example.org', owner: null, credentialKind: 'gitlab_bot', scopes: ['read_api'],
    canWrite: false, tokenExpiresAt: '2027-03-01T00:00:00Z', forgeVersion: '17.4.1', internalNetwork: true,
    caSubject: 'CN=Example Internal Root CA', caNotAfter: '2030-01-01T00:00:00Z', encryptionState: 'current',
    lastDiscovery: FORGE_DISCOVERY, importedTargets: 5,
    createdAt: '2026-09-01T09:00:00Z', createdBy: 'c.moreau', probedAt: '2026-09-18T07:00:00Z',
    updatedAt: '2026-09-01T09:00:00Z', updatedBy: 'c.moreau'
};

/** A repository as the forge listed it, in the shape the discovery and the selection both carry. */
const forgeRepository = (forgeId: string, fullPath: string, changes: Record<string, unknown> = {}) => {
    const parts = fullPath.split('/');
    return {
        id: Number(forgeId), connectionId: FORGE_ID, forgeId, fullPath,
        namespacePath: parts.slice(0, -1).join('/'), name: parts[parts.length - 1],
        defaultBranch: 'main', archived: false, fork: false, visibility: 'private', language: 'Java',
        lastActivityAt: '2026-09-15T10:00:00Z', sizeBytes: null,
        httpUrl: `https://git.example.org/${fullPath}.git`, sshUrl: `git@git.example.org:${fullPath}.git`,
        webUrl: `https://git.example.org/${fullPath}`, personal: false,
        firstSeenAt: '2026-09-18T08:01:00Z', firstSeenBy: 12, lastSeenAt: '2026-09-18T08:01:00Z', lastSeenBy: 12,
        changeSummary: null,
        ...changes
    };
};
const FORGE_NEW = [
    forgeRepository('201', 'payments/orion/gateway', { lastActivityAt: '2026-09-17T16:20:00Z' }),
    forgeRepository('202', 'payments/orion/ledger', { language: 'Kotlin', lastActivityAt: '2026-09-16T09:45:00Z' }),
    forgeRepository('203', 'data/reporting/report-builder', { language: 'Python', lastActivityAt: '2026-09-12T13:05:00Z' })
];

/** The same estate on github.com, whose fine-grained token reports no scopes and expires next week. */
const GITHUB_CONNECTION = {
    ...FORGE_CONNECTION,
    id: '2b7e9d40-5c13-4a86-b1f2-7d0e3a9c6b51', name: 'GitHub — example-org', kind: 'github', edition: 'github_com',
    baseUrl: 'https://api.github.com', owner: 'example-org', credentialKind: 'github_fine_grained', scopes: null,
    canWrite: null, tokenExpiresAt: '2026-09-25T00:00:00Z', forgeVersion: null, internalNetwork: false,
    caSubject: null, caNotAfter: null, lastDiscovery: null, importedTargets: 0,
    createdAt: '2026-09-15T13:00:00Z', probedAt: '2026-09-18T07:00:00Z', updatedAt: '2026-09-15T13:00:00Z'
};

/**
 * The monitored repositories, shaped from `openapi.json` and not from memory: a first attempt
 * guessed the fields and the table never rendered — `openIssues` is required and was missing, and
 * the criticality is `tier`. Reading the contract is how a fixture stops being a second opinion
 * about the server.
 */
const REPOSITORIES = [
    { id: 5, url: 'ssh://git@example.invalid/helios-portal.git', branch: 'main',
      displayName: 'helios-portal', name: 'helios-portal', subPath: null,
      openIssues: 214, tier: 'TIER_1_MISSION_CRITICAL', scanIntervalMinutes: 1440, scanCron: null, scanManualOnly: false,
      schedule: { mode: 'interval', intervalMinutes: 1440 },
      sshKeyId: null, httpsTokenId: null, requiredAgentLabel: null, lastScheduledScanAt: '2026-09-17T21:00:00Z',
      projectId: 11, projectName: 'Helios portal', detectedLanguages: ['java', 'typescript'],
      lastScan: { id: 34, status: 'completed', createdAt: '2026-09-17T21:04:00Z', error: null } },
    { id: 6, url: 'ssh://git@example.invalid/basalt-libs.git', branch: 'master',
      displayName: 'basalt-libs', name: 'basalt-libs', subPath: null,
      openIssues: 37, tier: 'TIER_3_INTERNAL', scanIntervalMinutes: null, scanCron: '0 3 * * *', scanManualOnly: false,
      schedule: { mode: 'cron', intervalMinutes: null },
      sshKeyId: null, httpsTokenId: null, requiredAgentLabel: null, lastScheduledScanAt: '2026-09-16T03:00:00Z',
      projectId: 12, projectName: 'Shared libraries', detectedLanguages: ['java', 'python'],
      lastScan: { id: 30, status: 'failed', createdAt: '2026-09-16T03:11:00Z',
                  error: 'clone refused' } }
];

/** A repository the forge import has just created: cloned over HTTPS, its first scan queued. */
const ORION_GATEWAY = {
    id: 8, url: 'https://git.example.org/payments/orion/gateway.git', branch: 'main',
    displayName: 'orion-gateway', name: 'orion-gateway', subPath: null,
    openIssues: 0, tier: 'TIER_2_BUSINESS_OPERATIONAL', scanIntervalMinutes: null, scanCron: null, scanManualOnly: false,
    schedule: { mode: 'default', intervalMinutes: 10080 },
    sshKeyId: null, httpsTokenId: GIT_TOKENS[0].id, requiredAgentLabel: null, lastScheduledScanAt: null,
    projectId: null, projectName: null, detectedLanguages: [],
    lastScan: { id: 36, status: 'pending', createdAt: '2026-09-18T11:58:00Z', error: null }
};

/** The API key helios-portal's pipeline delivers its documents with — one key, one declared source. */
const HELIOS_CI_KEY = '0d4f7a2c-9b61-4e38-a5c0-8e2b6d1f9c47';

/**
 * The tracker's settings as `Setting` labels and explains them, word for word: the screen shows the
 * server's help wherever the bundle has no translation of its own, so a stub with blank help would
 * photograph a sparser card than any installation shows.
 */
const TICKET_SETTINGS: Record<string, { label: string; help: string }> = {
    ticket_provider: {
        label: 'Provider',
        help: '"gitlab", "jira", or "none" to disable. A ticket is opened for any issue that would fail a build'
        + ' under the gate policy — there is no second threshold, so that one single place defines "serious'
        + ' enough to act on".'
    },
    ticket_base_url: {
        label: 'Tracker URL',
        help: 'An internal destination is accepted here, unlike the webhook: a self-hosted GitLab or Jira '
        + 'commonly lives on an internal network. The instance metadata endpoint stays refused.'
    },
    ticket_project: {
        label: 'Project',
        help: 'The GitLab path ("group/project"), the GitHub repository ("owner/repository") or the Jira '
        + 'project key ("SEC"). Set by an administrator only: the tracker token goes wherever this points, '
        + 'on the tracker\'s host.'
    },
    ticket_token: {
        label: 'Access token',
        help: 'Grants write access to the tracker, which is a different class of secret from a webhook URL: it '
        + 'is therefore encrypted at rest like an SSH key, not stored in the clear alongside the other '
        + 'settings. Written only by `PUT /api/v1/settings/ticket-token`.'
    },
    ticket_webhook_secret: {
        label: 'Inbound webhook secret',
        help: 'Authenticates the tracker calling **us**, which is the opposite direction from the access token '
        + 'above. The webhook route is anonymous by necessity — Jira holds no session — and it moves a '
        + 'triage decision, so without this an anonymous caller who guesses a ticket reference can close a '
        + 'finding. GitLab sends `X-Gitlab-Token` verbatim; GitHub sends `X-Hub-Signature-256` as '
        + 'HMAC-SHA256 over the raw body; Jira and ServiceNow have no convention, so a shared token in '
        + '`X-Vectispire-Token` is accepted for those. **While it is empty the route refuses every call** '
        + 'with a 403 telling the tracker the webhook is not configured: set it, then set the same value in'
        + ' the tracker. Encrypted at rest and written only by `PUT '
        + '/api/v1/settings/ticket-webhook-secret`.'
    },
    ticket_token_expires_on: {
        label: 'Token expiry date',
        help: 'The date the access token stops working, as YYYY-MM-DD, for a tracker that does not report it — '
        + 'Jira and ServiceNow. GitLab and GitHub report their tokens\' expiry, read when the token is '
        + 'saved and daily after; this date applies to them only when they report none. The settings screen'
        + ' announces it fourteen days ahead; empty, the expiry is shown as unknown. Set by an '
        + 'administrator only, like the token it describes.'
    },
    ticket_user: {
        label: 'Jira account',
        help: 'The account address, required by Jira alongside the token for basic authentication. GitLab does '
        + 'not use it. Set by an administrator only, like the token it travels with.'
    },
    ticket_issue_type: {
        label: 'Jira issue type',
        help: 'The type name in the target project. GitLab does not use it.'
    },
    ticket_labels: {
        label: 'Labels',
        help: 'Comma-separated, applied to every ticket opened.'
    },
    ticket_allow_private_url: {
        label: 'Allow an internal URL',
        help: 'On by default. Clear it for a deployment that only uses a hosted tracker.'
    },
    ticket_ca_pem: {
        label: 'Tracker CA (PEM)',
        help: 'For a tracker whose certificate comes from your organisation\'s own CA: paste that CA\'s '
        + 'certificate in PEM form (-----BEGIN CERTIFICATE-----), a root and its intermediates if need be. '
        + 'Used for the tracker only, and **in place of** the server\'s trust store — the public CAs are '
        + 'then not trusted for it; the tracker\'s name is still verified. Empty, the server\'s trust store'
        + ' applies. Set by an administrator only: it decides whom the tracker token is presented to.'
    }
};

/** A CA certificate as a reader pastes one: shortened, since only its shape is on screen. */
const EXAMPLE_CA_PEM = [
    '-----BEGIN CERTIFICATE-----',
    'MIIBszCCAVmgAwIBAgIUQ2V4YW1wbGUgSW50ZXJuYWwgUm9vdCBDQTAKBggqhkjO',
    'PQQDAjAmMSQwIgYDVQQDDBtFeGFtcGxlIEludGVybmFsIFJvb3QgQ0EwHhcNMjUw',
    '-----END CERTIFICATE-----'
].join('\n');

/**
 * The analysis plugins (decision 0017): the house rules every Java project runs, signed; a Python
 * checker, which reads nothing on a Java repository — not applicable, not absent; and a Terraform
 * policy that needs the network, said so on its row.
 */
const pluginManifest = (id: string, name: string, languages: string[], network: boolean, digestSeed: string) => ({
    id, name, image: `registry.example/sec/${id}@sha256:${digestSeed.repeat(64 / digestSeed.length)}`,
    languages, arguments: ['--sarif', '{output}', '{source}'], output: 'results.sarif', exit_codes: [0, 1],
    network, network_justification: network ? 'Reads the module registry to resolve provider versions' : null,
    timeout_seconds: 600,
    signature: { identity: `https://ci.example.org/sec/${id}/.ci/release@refs/tags/v1.3.0`,
                 issuer: 'https://ci.example.org/oidc', public_key: null }
});
const plugin = (manifest: ReturnType<typeof pluginManifest>, enabled: boolean, digest: string) => ({
    id: manifest.id, name: manifest.name, manifest, manifestDigest: digest, enabled,
    createdAt: '2026-08-14T08:00:00Z', createdBy: 'c.moreau', updatedAt: null, updatedBy: null, unsignedWaiver: null
});
const HOUSE_RULES = plugin(pluginManifest('house-rules', 'Example house rules', ['java', 'kotlin'], false, '3a9f'), true,
                           '8e41c07d2b95f3a6e0d1c48b7f2a9e53d6b0c1f47a8e2d95b3c6f0a1e7d4b28c');
const PYTHON_TYPING = plugin(pluginManifest('python-typing', 'Strict typing for Python', ['python'], false, '51c2'), true,
                             '2f7b9d1e4a6c8e0b3d5f7a9c1e3b5d7f9a2c4e6b8d0f1a3c5e7b9d2f4a6c8e0b');
const TERRAFORM_POLICY = plugin(pluginManifest('terraform-policy', 'Terraform estate policy', ['terraform'], true, 'b7e0'),
                                false, '9c2e4b6d8f0a1c3e5b7d9f2a4c6e8b0d1f3a5c7e9b2d4f6a8c0e1b3d5f7a9c2e');

/**
 * A report plugin (decision 0035): approved by a second person, with a newer version awaiting the
 * same — the project's reports run the approved digest until then.
 */
const REPORT_MANIFEST = {
    id: 'quarterly-risk-summary', name: 'Quarterly risk summary',
    image: `registry.example/reports/quarterly-risk-summary@sha256:${'4d2a'.repeat(16)}`,
    export_schema: 1, arguments: ['--in', '{input}', '--out', '{output}'], output: 'summary.xlsx',
    media_type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    max_output_bytes: 20971520, timeout_seconds: 120,
    signature: { identity: 'https://ci.example.org/reports/quarterly-risk-summary/.ci/release@refs/tags/v2.1.0',
                 issuer: 'https://ci.example.org/oidc', public_key: null }
};
const REPORT_APPROVED_DIGEST = 'a1c3e5b7d9f2a4c6e8b0d1f3a5c7e9b2d4f6a8c0e1b3d5f7a9c2e4b6d8f0a1c3';
const REPORT_PENDING_MANIFEST = {
    digest: 'e8b0d2f4a6c8e1b3d5f7a9c0e2b4d6f8a1c3e5b7d9f0a2c4e6b8d1f3a5c7e9b2', status: 'pending_approval',
    manifest: { ...REPORT_MANIFEST, timeout_seconds: 180,
                signature: { ...REPORT_MANIFEST.signature,
                             identity: 'https://ci.example.org/reports/quarterly-risk-summary/.ci/release@refs/tags/v2.2.0' } },
    registeredAt: '2026-09-16T10:00:00Z', registeredBy: 'n.faure', approvedAt: null, approvedBy: null,
    approvalFourEyes: null, withdrawnAt: null, withdrawnBy: null, withdrawalJustification: null
};
const REPORT_PLUGIN = {
    id: REPORT_MANIFEST.id, name: REPORT_MANIFEST.name, approvedDigest: REPORT_APPROVED_DIGEST,
    pendingDigest: REPORT_PENDING_MANIFEST.digest, enabled: true,
    createdAt: '2026-09-01T08:00:00Z', createdBy: 'n.faure', updatedAt: '2026-09-16T10:00:00Z', updatedBy: 'n.faure',
    manifests: [
        REPORT_PENDING_MANIFEST,
        { ...REPORT_PENDING_MANIFEST, digest: REPORT_APPROVED_DIGEST, status: 'approved', manifest: REPORT_MANIFEST,
          registeredAt: '2026-09-01T08:00:00Z', approvedAt: '2026-09-02T09:30:00Z', approvedBy: 'c.moreau',
          approvalFourEyes: true }
    ]
};

/** A document the plugin produced and the package signed, then the attempt before it, refused. */
const PRODUCED_REPORT = {
    id: 7, projectId: 11, projectName: 'Helios portal', pluginId: REPORT_MANIFEST.id, state: 'produced',
    reason: null, detail: null, requestedAt: '2026-09-15T08:00:00Z', requestedBy: 'n.faure',
    startedAt: '2026-09-15T08:00:05Z', exportedAt: '2026-09-15T08:00:06Z', finishedAt: '2026-09-15T08:00:31Z',
    manifestDigest: REPORT_APPROVED_DIGEST, imageDigest: `sha256:${'4d2a'.repeat(16)}`,
    signerIdentity: REPORT_MANIFEST.signature.identity, signerIssuer: REPORT_MANIFEST.signature.issuer,
    signerKeySha256: null, exportSchemaVersion: '1.0',
    exportSha256: '6b8d0f2a4c6e8b1d3f5a7c9e2b4d6f8a0c1e3b5d7f9a2c4e6b8d0f1a3c5e7b9d', exportSize: 48213,
    exitCode: 0, outputSize: 2_116_402,
    outputSha256: 'd3f5a7c9e2b4d6f8a0c1e3b5d7f9a2c4e6b8d0f1a3c5e7b9d2f4a6c8e0b1d3f5',
    outputMediaType: REPORT_MANIFEST.media_type, signingKeyId: 'installation-2026',
    packageSha256: 'f1a3c5e7b9d2f4a6c8e0b1d3f5a7c9e2b4d6f8a0c1e3b5d7f9a2c4e6b8d0f1a3', productVersion: '0.11.0',
    withdrawnAt: null, withdrawnBy: null, withdrawalJustification: null
};
const FAILED_REPORT = {
    ...PRODUCED_REPORT, id: 6, state: 'failed', reason: 'exit_code', detail: 'the export has no issues part',
    requestedAt: '2026-09-12T16:40:00Z', startedAt: '2026-09-12T16:40:04Z', exportedAt: '2026-09-12T16:40:05Z',
    finishedAt: '2026-09-12T16:40:09Z', exitCode: 1, outputSize: null, outputSha256: null, outputMediaType: null,
    signingKeyId: null, packageSha256: null
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
            // **Then the second picker opened, and left open on purpose.** A closed one cuts its label
            // after the branch, so the count each scan offers — "7 issues", which used to be a bare
            // "7" — was never in the picture. Opened to the end, its two options are the shot.
            await page.locator('p-select', { has: page.locator('#diff-to') }).click();
            await expect(page.getByRole('option')).toHaveCount(2, { timeout: 15_000 });
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
            // The failing targets carry the violations the gate verdicts capture counts, so the
            // Violations column reads four and two where the verdict register says four and two.
            await stub(page, '**/api/v1/dashboard', asSchema('DashboardOverview', DASHBOARD_OVERVIEW));
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
            // **The dated marker** (decision 0036): the day this installation's grades changed
            // formula, inside the window, so the line is drawn on both charts and said in words below
            // them. The backlog does not move with it — the formula grades, it does not count.
            await stub(page, '**/api/v1/dashboard/trends*', asSchema('Trends', {
                points: days, mean_days_to_resolve: 11.4, resolved_in_window: 21,
                score_formula_changed_on: '2026-09-15'
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
            // The velocity line, by its figures — each edition in its own decimal mark: "55.3 %", "55,3 %".
            await expect(page.getByText(/55[.,]3\s?%/).first()).toBeVisible({ timeout: 15_000 });
            // The dated line in words, by its date: a canvas draws nothing a test can read.
            await expect(page.getByTestId('score-formula-change')).toContainText('2026-09-15', { timeout: 15_000 });
            await shoot(page, 'dashboard', locale);

            // **The lower half, from the portfolio down.** The grade distribution, the weakest
            // target, and the two tables whose columns changed meaning — violations of the gate,
            // issues of a scan — sit below the fold of the first capture.
            await expect(page.getByTestId('portfolio-weakest')).toContainText('helios-portal', { timeout: 15_000 });
            // With a margin the height of the top bar, which stays fixed over the page: aligned to
            // the very top, the card's title scrolled underneath it.
            await page.getByTestId('portfolio-distribution').evaluate((node) => {
                const card = node.closest('p-card') as HTMLElement | null;
                if (!card) return;
                card.style.scrollMarginTop = '5rem';
                card.scrollIntoView({ block: 'start', behavior: 'instant' });
            });
            await shoot(page, 'dashboard-portfolio', locale);
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
            await stub(page, '**/api/v1/repositories*', REPOSITORIES);
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
                backlogBySeverity: { critical: 4, high: 12, medium: 31, low: 365 },
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

        test('repository form', async ({ page }, testInfo) => {
            const locale = edition(testInfo.project.name);
            await stubEverything(page);
            // **An HTTPS clone, because that is what changed on this form.** The credential follows
            // the URL: an `https://` address offers no SSH key, and only the tokens bound to its host
            // — so the internal GitLab's token is offered and the other two are not.
            await stub(page, '**/api/v1/repositories*', [...REPOSITORIES, ORION_GATEWAY]);
            await stub(page, '**/api/v1/git-tokens', GIT_TOKENS);
            await stub(page, '**/api/v1/rule-sets/coverage', RULE_COVERAGE);
            await enterApp(page, locale);
            await openScreen(page, '/repositories');

            await expect(page.getByText('orion-gateway').first()).toBeVisible({ timeout: 15_000 });
            // By the edit button's accessible name, which carries the URL — the one label read here,
            // in both editions' words, because the three buttons of a row differ by nothing else.
            await page.getByRole('button', { name: new RegExp(`^(Edit|Modifier) ${ORION_GATEWAY.url}$`) }).click();
            await expect(page.locator('#url')).toHaveValue(ORION_GATEWAY.url, { timeout: 15_000 });
            // The dialog scrolls on its own; the credential is in its lower half, so it is brought up.
            const token = page.getByRole('dialog').locator('p-select', { has: page.locator('#https-token') });
            await token.evaluate((node) => node.scrollIntoView({ block: 'center', behavior: 'instant' }));
            await expect(token).toContainText('gitlab-read (git.example.org)');
            await shoot(page, 'repository-form', locale);
        });

        test('repository imports', async ({ page }, testInfo) => {
            const locale = edition(testInfo.project.name);
            await stubEverything(page);
            await stub(page, '**/api/v1/repositories*', REPOSITORIES);
            await stub(page, '**/api/v1/rule-sets/coverage', RULE_COVERAGE);
            // What helios-portal's pipeline sends beside the scans: the coverage and the test
            // report of its last build, and the SARIF documents of two declared sources — the CI's
            // SonarQube on every build, and a penetration test's ZAP report once. The figures are
            // what the tools stated; the screen says so, and so does the capture.
            await stub(page, '**/api/v1/repositories/5/coverage-imports', [
                { id: 18, repoId: 5, sourceId: 3, sourceSlug: 'helios-ci', apiKeyId: HELIOS_CI_KEY,
                  importedBy: 'helios-ci-key', importedAt: '2026-09-17T20:58:00Z', format: 'jacoco',
                  toolVersion: '0.8.12', commit: '9c41e07b2d5f8a13e6b0c47d2a9f1e85b3c6d702', branch: 'main',
                  linesCovered: 18342, linesTotal: 24117, branchesCovered: 4210, branchesTotal: 6630,
                  documentSha256: '1f0c9a7e3b5d24c8e6f1a0b9d7c3e5f2a4b6c8d0e1f3a5b7c9d0e2f4a6b8c1d3',
                  packagesState: null }
            ]);
            await stub(page, '**/api/v1/repositories/5/test-report-imports', [
                { id: 22, repoId: 5, sourceId: 3, sourceSlug: 'helios-ci', apiKeyId: HELIOS_CI_KEY,
                  importedBy: 'helios-ci-key', importedAt: '2026-09-17T20:59:00Z', format: 'junit',
                  commit: '9c41e07b2d5f8a13e6b0c47d2a9f1e85b3c6d702', branch: 'main',
                  documentsCount: 214, suitesCount: 214, testsCount: 1873, failuresCount: 2, errorsCount: 0,
                  skippedCount: 11,
                  documentSha256: '7a2e4c6b8d0f1e3a5c7b9d2f4e6a8c0b1d3f5e7a9c2b4d6f8e0a1c3b5d7f9e2a' }
            ]);
            const sarif = (id: number, slug: string, keyName: string, at: string, tool: string,
                           results: number, created: number, resolved: number, reopened: number, sha: string) => ({
                id, repoId: 5, sourceId: slug === 'helios-ci' ? 3 : 4, sourceSlug: slug, apiKeyId: HELIOS_CI_KEY,
                importedBy: keyName, importedAt: at, tools: [tool], toolKeys: [tool.toLowerCase()],
                resultsCount: results, createdCount: created, resolvedCount: resolved, reopenedCount: reopened,
                documentSha256: sha
            });
            await stub(page, '**/api/v1/repositories/5/sarif-imports', [
                sarif(51, 'helios-ci', 'helios-ci-key', '2026-09-17T21:00:00Z', 'SonarQube', 37, 2, 5, 0,
                      '3f9a1c7e5b2d4f6a8c0e1b3d5f7a9c2e4b6d8f0a1c3e5b7d9f2a4c6e8b0d1f3a'),
                sarif(48, 'helios-ci', 'helios-ci-key', '2026-09-10T20:57:00Z', 'SonarQube', 40, 4, 1, 1,
                      'b8d0f2a4c6e8b1d3f5a7c9e2b4d6f8a0c1e3b5d7f9a2c4e6b8d0f1a3c5e7b9d2'),
                sarif(46, 'appsec-pentest', 'pentest-upload-key', '2026-09-04T15:12:00Z', 'ZAP', 6, 6, 0, 0,
                      'c5e7b9d2f4a6c8e0b1d3f5a7c9e2b4d6f8a0c1e3b5d7f9a2c4e6b8d0f1a3c5e7')
            ]);
            await enterApp(page, locale);
            await openScreen(page, '/repositories');

            await expect(page.getByText('basalt-libs').first()).toBeVisible({ timeout: 15_000 });
            // helios-portal is the first card; its button names it, which the dialog header repeats.
            await page.getByTestId('sarif-imports-btn').first().click();
            await expect(page.getByRole('dialog')).toContainText('helios-portal', { timeout: 15_000 });
            await expect(page.getByTestId('sarif-import')).toHaveCount(3, { timeout: 15_000 });
            await expect(page.getByTestId('tests-count')).toHaveText('1873');
            await shoot(page, 'repository-imports', locale);
        });

        test('https tokens', async ({ page }, testInfo) => {
            const locale = edition(testInfo.project.name);
            await stubEverything(page);
            await stub(page, '**/api/v1/git-tokens', GIT_TOKENS);
            await enterApp(page, locale);
            await openScreen(page, '/git-tokens');

            await expect(page.getByText('bitbucket-legacy-read').first()).toBeVisible({ timeout: 15_000 });
            await shoot(page, 'git-tokens', locale);
        });

        test('solutions and projects', async ({ page }, testInfo) => {
            const locale = edition(testInfo.project.name);
            await stubEverything(page);
            await stub(page, '**/api/v1/solutions', SOLUTION_TREE);
            await enterApp(page, locale);
            await openScreen(page, '/solutions');

            await expect(page.getByText('Shared libraries').first()).toBeVisible({ timeout: 15_000 });
            await expect(page.getByTestId('unfiled')).toContainText('registry.example/batch-runner:2026.09');
            await shoot(page, 'solutions', locale);
        });

        test('project reports', async ({ page }, testInfo) => {
            const locale = edition(testInfo.project.name);
            await stubEverything(page);
            await stub(page, '**/api/v1/solutions', SOLUTION_TREE);
            const project = SOLUTION_TREE.solutions[0].projects[0];
            await stub(page, '**/api/v1/projects/11', {
                ...project, solution: { id: 1, name: 'Customer services' }
            });
            // **Graded by its weakest target** (decision 0036): helios-portal's F at 18, the
            // dashboard scoreboard's, and the risk points of both targets' open backlog.
            await stub(page, '**/api/v1/projects/11/compliance', {
                kind: 'project', id: 11, name: 'Helios portal', partial: false, targetCount: 2,
                compliance: {
                    evaluations: [
                        { framework: 'NIS_2', overallStatus: 'PARTIAL', scorePercentage: 61, controls: [] },
                        { framework: 'ISO_27001', overallStatus: 'PARTIAL', scorePercentage: 66, controls: [] },
                        { framework: 'EU_CRA', overallStatus: 'NON_COMPLIANT', scorePercentage: 48, controls: [] }
                    ],
                    mttr: { mttrBySeverityDays: { critical: 3.2, high: 6.8 }, overallMttrDays: 9.6, resolvedCount: 18 },
                    overdueCount: 3, dueSoonCount: 1, totalMonitoredTargets: 2, passingGateTargets: 0,
                    observedTargets: 2, freshTargets: 2,
                    targets: [
                        { targetId: 'REPOSITORY:5', name: 'helios-portal', type: 'REPOSITORY', gateStatus: 'FAILED',
                          openIssuesCount: 214, overdueCount: 2, overallStatus: 'PARTIAL', overallScore: 58,
                          frameworkScores: { NIS_2: 58, ISO_27001: 63, EU_CRA: 44 } },
                        { targetId: 'CONTAINER:3', name: 'registry.example/api:1.4', type: 'CONTAINER',
                          gateStatus: 'FAILED', openIssuesCount: 58, overdueCount: 1, overallStatus: 'PARTIAL',
                          overallScore: 66, frameworkScores: { NIS_2: 64, ISO_27001: 69, EU_CRA: 52 } }
                    ]
                },
                scorecard: {
                    targetId: 11, targetKind: 'project', targetName: 'Helios portal', score: 18, grade: 'F',
                    riskPoints: 563.5,
                    weakestTarget: { targetKind: 'repository', targetId: 5, targetName: 'helios-portal',
                                     score: 18, grade: 'F', riskPoints: 412.5 },
                    totalTargets: 2, observedTargets: 2, openKevCount: 1, openCriticalCount: 4, openHighCount: 10,
                    licenseViolationCount: 0, overdueCount: 3, hasAttestation: true,
                    recommendations: ['Fix the actively exploited vulnerability first.']
                }
            });
            await stub(page, '**/api/v1/projects/11/components', {
                kind: 'project', id: 11, name: 'Helios portal', partial: false, complete: true,
                targets: [
                    { kind: 'repository', id: 5, name: 'helios-portal', scanId: 34, scannedAt: '2026-09-17T21:04:00Z',
                      inventory: 'listed', componentCount: 2 },
                    { kind: 'container', id: 3, name: 'registry.example/api:1.4', scanId: 32,
                      scannedAt: '2026-09-17T18:06:00Z', inventory: 'listed', componentCount: 1 }
                ],
                components: [
                    { name: 'log4j-core', version: '2.14.1', purl: 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1',
                      type: 'library', sources: ['scanner'], targets: [{ kind: 'repository', id: 5, name: 'helios-portal' }] },
                    { name: 'spring-webmvc', version: '6.1.12', purl: 'pkg:maven/org.springframework/spring-webmvc@6.1.12',
                      type: 'library', sources: ['scanner'], targets: [{ kind: 'repository', id: 5, name: 'helios-portal' }] },
                    { name: 'libcurl4', version: '7.88.1-10+deb12u3', purl: 'pkg:deb/debian/libcurl4@7.88.1-10%2Bdeb12u3',
                      type: 'library', sources: ['scanner'],
                      targets: [{ kind: 'container', id: 3, name: 'registry.example/api:1.4' }] }
                ]
            });
            await stub(page, '**/api/v1/report-plugins', [REPORT_PLUGIN]);
            await stub(page, '**/api/v1/projects/11/report-plugins', [
                { id: 1, pluginId: REPORT_PLUGIN.id, pluginName: REPORT_PLUGIN.name, projectId: 11,
                  activatedAt: '2026-09-08T10:00:00Z', activatedBy: 'c.moreau' }
            ]);
            // A document produced and signed, and the attempt before it, which the plugin refused
            // to finish: what a run says when it fails, beside what it says when it does not.
            await stub(page, '**/api/v1/projects/11/reports', [PRODUCED_REPORT, FAILED_REPORT]);
            await enterApp(page, locale);
            await openScreen(page, '/solutions');
            await page.locator('a[href="/projects/11"]').first().click();
            await expect(page).toHaveURL(/\/projects\/11(\?|#|$)/, { timeout: 15_000 });

            await expect(page.getByTestId(`run-${PRODUCED_REPORT.id}`)).toBeVisible({ timeout: 15_000 });
            await page.getByTestId('project-reports').evaluate((node) => {
                (node as HTMLElement).style.scrollMarginTop = '5rem';
                node.scrollIntoView({ block: 'start', behavior: 'instant' });
            });
            await shoot(page, 'project-reports', locale);
        });

        test('report plugins', async ({ page }, testInfo) => {
            const locale = edition(testInfo.project.name);
            await stubEverything(page);
            // One plugin approved and a new version of it awaiting a second person, and one never
            // approved, which nothing can switch on — the two states the four-eyes rule produces.
            await stub(page, '**/api/v1/report-plugins', [
                REPORT_PLUGIN,
                { ...REPORT_PLUGIN, id: 'audit-pack-pdf', name: 'Audit pack (PDF)', approvedDigest: null,
                  pendingDigest: 'c3e5a7b9d1f2a4c6e8b0d2f4a6c8e1b3d5f7a9c0e2b4d6f8a1c3e5b7d9f0a2c4', enabled: false, createdAt: '2026-09-16T14:00:00Z', updatedAt: null, updatedBy: null,
                  manifests: [{
                      ...REPORT_PENDING_MANIFEST,
                      digest: 'c3e5a7b9d1f2a4c6e8b0d2f4a6c8e1b3d5f7a9c0e2b4d6f8a1c3e5b7d9f0a2c4',
                      registeredAt: '2026-09-16T14:00:00Z',
                      manifest: { ...REPORT_MANIFEST, id: 'audit-pack-pdf', name: 'Audit pack (PDF)',
                                  image: `registry.example/reports/audit-pack-pdf@sha256:${'7c1e'.repeat(16)}`,
                                  output: 'audit-pack.pdf', media_type: 'application/pdf' }
                  }] }
            ]);
            await enterApp(page, locale);
            await openScreen(page, '/report-plugins');

            await expect(page.getByTestId(`report-plugin-${REPORT_PLUGIN.id}`)).toBeVisible({ timeout: 15_000 });
            await page.getByTestId(`open-${REPORT_PLUGIN.id}`).click();
            await expect(page.getByTestId('report-plugin-detail')).toBeVisible({ timeout: 15_000 });
            await shoot(page, 'report-plugins', locale);
        });

        test('plugins', async ({ page }, testInfo) => {
            const locale = edition(testInfo.project.name);
            await stubEverything(page);
            await stub(page, '**/api/v1/plugins', [HOUSE_RULES, PYTHON_TYPING, TERRAFORM_POLICY]);
            await stub(page, '**/api/v1/plugins/house-rules', HOUSE_RULES);
            await stub(page, '**/api/v1/plugins/house-rules/projects', [
                { id: 1, pluginId: 'house-rules', projectId: 11, projectName: 'Helios portal', solutionId: 1,
                  solutionName: 'Customer services', activatedAt: '2026-08-20T09:00:00Z', activatedBy: 'c.moreau' },
                { id: 2, pluginId: 'house-rules', projectId: 12, projectName: 'Shared libraries', solutionId: 2,
                  solutionName: 'Platform', activatedAt: '2026-08-20T09:02:00Z', activatedBy: 'c.moreau' }
            ]);
            await enterApp(page, locale);
            await openScreen(page, '/plugins');

            await expect(page.getByTestId('plugin-terraform-policy')).toBeVisible({ timeout: 15_000 });
            // Opened, because what the registry has to show is a manifest — the image by digest,
            // what it reads, whether it may reach the network — and the projects that run it.
            await page.getByTestId('plugin-house-rules').locator('p-button[icon="pi pi-eye"] button').click();
            await expect(page.getByTestId('plugin-detail')).toContainText('Shared libraries', { timeout: 15_000 });
            await shoot(page, 'plugins', locale);
        });

        test('declared sources', async ({ page }, testInfo) => {
            const locale = edition(testInfo.project.name);
            await stubEverything(page);
            await stub(page, '**/api/v1/solutions', SOLUTION_TREE);
            await stub(page, '**/api/v1/repositories*', REPOSITORIES);
            // The keys the declaration form offers: the ones that deliver, each holding the scope
            // `ApiKeyScope` withholds by default.
            const deliveryKey = (id: string, name: string, prefix: string, createdAt: string) => ({
                id, name, prefix, scopes: ['sarif_import'], targetKind: null, targetId: null, targetLabel: null,
                createdAt, lastUsedAt: '2026-09-17T21:00:00Z', expiresAt: null, isExpired: false
            });
            await stub(page, '**/api/v1/api-keys', [
                deliveryKey(HELIOS_CI_KEY, 'helios-ci-key', 'vsp_Hc4q', '2026-08-11T09:25:00Z'),
                deliveryKey('e2a9c4b7-6d13-4f58-8b02-3c7e1a9d5f46', 'pentest-upload-key', 'vsp_Pt7w', '2026-09-01T13:55:00Z'),
                deliveryKey('f7b3d1e9-2c46-4a80-9e5d-0b8f6c2a4d13', 'platform-build-key', 'vsp_Pb2k', '2026-08-25T11:15:00Z')
            ]);
            // **What each source delivers, which is what the column was renamed for.** A source was
            // a SARIF source; it now declares the kinds of document its key may send — findings,
            // coverage, test reports, a build SBOM — and one key carries one source.
            await stub(page, '**/api/v1/sarif-sources', [
                { id: 3, slug: 'helios-ci', name: 'Helios portal pipeline', apiKeyId: HELIOS_CI_KEY,
                  apiKeyName: 'helios-ci-key', projectId: 11, repositoryId: null, tools: ['SonarQube'],
                  kinds: ['sarif', 'coverage', 'test_report'], enabled: true,
                  createdAt: '2026-08-11T09:30:00Z', createdBy: 'c.moreau' },
                { id: 4, slug: 'appsec-pentest', name: 'Yearly penetration test', apiKeyId: 'e2a9c4b7-6d13-4f58-8b02-3c7e1a9d5f46',
                  apiKeyName: 'pentest-upload-key', projectId: null, repositoryId: 5, tools: ['ZAP'],
                  kinds: ['sarif'], enabled: true, createdAt: '2026-09-01T14:00:00Z', createdBy: 'c.moreau' },
                { id: 5, slug: 'platform-build', name: 'Shared libraries build', apiKeyId: 'f7b3d1e9-2c46-4a80-9e5d-0b8f6c2a4d13',
                  apiKeyName: 'platform-build-key', projectId: 12, repositoryId: null,
                  tools: ['CycloneDX Maven plugin', 'JaCoCo'], kinds: ['sbom', 'coverage'], enabled: true,
                  createdAt: '2026-08-25T11:20:00Z', createdBy: 'n.faure' },
                // Its key was revoked: the source still stands, and delivers nothing — said so.
                { id: 2, slug: 'legacy-scanner', name: 'Former SAST service', apiKeyId: null,
                  apiKeyName: null, projectId: 13, repositoryId: null, tools: ['Fortify'],
                  kinds: ['sarif'], enabled: false, createdAt: '2026-04-02T08:00:00Z', createdBy: 'admin' }
            ]);
            await enterApp(page, locale);
            await openScreen(page, '/sarif-sources');

            await expect(page.getByTestId('source-legacy-scanner')).toBeVisible({ timeout: 15_000 });
            await expect(page.getByTestId('source-helios-ci')).toContainText('Helios portal');
            await shoot(page, 'sarif-sources', locale);
        });

        test('forge connections', async ({ page }, testInfo) => {
            const locale = edition(testInfo.project.name);
            await stubEverything(page);
            await stub(page, '**/api/v1/forge-connections', [FORGE_CONNECTION, GITHUB_CONNECTION]);
            await enterApp(page, locale);
            await openScreen(page, '/forge-connections');

            await expect(page.getByTestId('connection')).toHaveCount(2, { timeout: 15_000 });
            await expect(page.getByTestId('connection-address').first()).toHaveText('https://git.example.org');
            await shoot(page, 'forge-connections', locale);
        });

        test('forge discovery, selection and import', async ({ page }, testInfo) => {
            const locale = edition(testInfo.project.name);
            await stubEverything(page);
            const base = `**/api/v1/forge-connections/${FORGE_ID}`;
            await stub(page, '**/api/v1/forge-connections', [FORGE_CONNECTION, GITHUB_CONNECTION]);
            await stub(page, base, FORGE_CONNECTION);
            // The run before this one, to show that a discovery is a dated observation and the
            // comparison is between two of them.
            await stub(page, `${base}/discoveries`, [
                FORGE_DISCOVERY,
                { ...FORGE_DISCOVERY, id: 9, repositoriesSeen: 39, requestsMade: 45, newCount: 39, changedCount: 0,
                  goneCount: null, requestedAt: '2026-09-04T08:00:00Z', startedAt: '2026-09-04T08:00:03Z',
                  finishedAt: '2026-09-04T08:01:02Z' }
            ]);
            await stub(page, `${base}/discoveries/12`, FORGE_DISCOVERY);
            await stub(page, `${base}/discoveries/12/repositories*`, {
                items: FORGE_NEW, limit: 50, offset: 0, total: 3
            });
            // Five of the forty-one the discovery saw, past the filters: the three new ones, one
            // already watched — so not selectable, and said why — and a personal project nobody
            // proposed.
            const candidate = (repository: ReturnType<typeof forgeRepository>, changes: Record<string, unknown> = {}) => ({
                repository, selectable: true, notSelectable: null, offered: true, presentAs: [], importedAs: null,
                proposedSolution: repository.namespacePath.split('/')[0],
                proposedProject: repository.namespacePath.split('/').slice(1).join('/') || null,
                ...changes
            });
            await stubByMethod(page, `${base}/discoveries/12/selection*`, {
                GET: {
                    discoveryId: 12, limit: 50, offset: 0, listed: 41, total: 5, unjudged: { fork: 2 },
                    items: [
                        ...FORGE_NEW.map((repository) => candidate(repository)),
                        candidate(forgeRepository('118', 'customer/helios/helios-portal'), {
                            selectable: false, notSelectable: 'already_present', offered: false, presentAs: [5]
                        }),
                        candidate(forgeRepository('164', 'j.martin/sandbox', { personal: true, language: null }), {
                            offered: false, proposedSolution: null, proposedProject: null
                        })
                    ]
                },
                POST: { discoveryId: 12, count: 2, selected: ['201', '202'], dropped: [] }
            });
            await stub(page, '**/api/v1/solutions', SOLUTION_TREE);
            await stub(page, '**/api/v1/git-tokens', GIT_TOKENS);
            // The two Orion repositories, into a solution and a project the import creates, cloned
            // with the internal GitLab's token.
            const gitlabRead = { kind: 'https_token', id: GIT_TOKENS[0].id, name: GIT_TOKENS[0].name };
            await stub(page, `${base}/imports/preview`, {
                connectionId: FORGE_ID, discoveryId: 12,
                targets: FORGE_NEW.slice(0, 2).map((repository) => ({
                    forgeId: repository.forgeId, fullPath: repository.fullPath, url: repository.httpUrl,
                    branch: 'main', credential: gitlabRead, solution: 'payments', project: 'orion',
                    visibleTo: null, firstScanNotBefore: null, warning: null
                })),
                skipped: [], refused: [],
                solutions: [{ name: 'payments', existingId: null }],
                projects: [{ name: 'orion', solution: 'payments', existingId: null, targets: 2, accounts: 0, teams: 0 }],
                credentials: [{ host: 'git.example.org', credential: gitlabRead, proposed: true, repositories: 2 }],
                // No first scan asked for — the box is left as it opens — so none is planned: each
                // target waits for its own slot of the default schedule.
                defaultIntervalDays: 7, visibilityMode: 'assigned', firstScans: null
            });
            await enterApp(page, locale);
            await openScreen(page, '/forge-connections');
            await page.getByTestId('connection-discover').first().click();
            await expect(page).toHaveURL(new RegExp(`/forge-connections/${FORGE_ID}`), { timeout: 15_000 });

            // **Discovery**: the last run's counters, and what it found that the run before had not.
            await expect(page.getByTestId('repositories')).toContainText('41', { timeout: 15_000 });
            await page.getByTestId('count-new').click();
            await expect(page.getByTestId('changed-row')).toHaveCount(3, { timeout: 15_000 });
            await shoot(page, 'forge-discovery', locale);

            // **Selection**: the proposed repositories ticked in one move, as an operator starts.
            await page.getByTestId('to-selection').click();
            await expect(page.getByTestId('candidate')).toHaveCount(5, { timeout: 15_000 });
            await page.getByTestId('op-proposed').click();
            await expect(page.getByTestId('tick').first()).toBeChecked({ timeout: 15_000 });
            // From the operations down: the filters above them fill the first screenful, and the
            // table is what an operator reads before going on.
            await page.getByTestId('op-proposed').evaluate((node) => {
                const row = (node.parentElement ?? node) as HTMLElement;
                row.style.scrollMarginTop = '5rem';
                row.scrollIntoView({ block: 'start', behavior: 'instant' });
            });
            await shoot(page, 'forge-selection', locale);

            // **Import**: the preview of what the import will create, before anything is.
            await page.getByTestId('to-import').click();
            await expect(page.getByTestId('visible-to')).toHaveCount(2, { timeout: 15_000 });
            // Centred on the plan — each repository with its address, credential and filing — which
            // sits below the placement and the credentials an operator may still change.
            await page.getByTestId('visible-to').first().evaluate((node) =>
                node.scrollIntoView({ block: 'center', behavior: 'instant' }));
            await shoot(page, 'forge-import', locale);
        });

        test('scan detail', async ({ page }, testInfo) => {
            const locale = edition(testInfo.project.name);
            await stubEverything(page);
            await stub(page, '**/api/v1/dashboard', DASHBOARD_OVERVIEW);
            await stub(page, '**/api/v1/rule-sets/coverage', RULE_COVERAGE);
            // **Seven issues, ten occurrences: the two counts the card now keeps apart.** An issue is
            // one fingerprint and carries no line; an occurrence is one place a tool reported it.
            // The leaked token sits on two lines of one file and the SQL string on three: seven
            // issues, ten rows below.
            const finding = (id: number, type: string, severity: string, identifier: string,
                             changes: Record<string, unknown> = {}) => ({
                id, type, severity, identifier, description: null, filePath: null, line: null, link: null,
                packageName: null, packageVersion: null, fixVersions: null, tool: null, toolName: null,
                toolVersion: null, ...changes
            });
            const sqlString = 'java.lang.security.audit.formatted-sql-string';
            const builder = 'src/main/java/portal/LegacyQueryBuilder.java';
            await stub(page, '**/api/v1/scans/34', {
                scan: { id: 34, status: 'completed', branch: 'main', targetKind: 'REPOSITORY', targetName: 'helios-portal',
                        targetId: 5, createdAt: '2026-09-17T21:04:00Z', durationMs: 91_000, findingsCount: 7,
                        newIssuesCount: 1, resolvedIssuesCount: 3, error: null, claimedBy: null, attempts: 1,
                        notBefore: null },
                projectType: 'maven', projectVersion: '4.2.0', subPath: null, hasSbom: true,
                examinedTypes: ['vulnerability', 'secret', 'iac', 'license', 'eol', 'sast', 'quality'],
                plugins: [
                    { pluginId: 'house-rules', state: 'produced', findings: 1, languages: ['java', 'kotlin'],
                      manifestDigest: HOUSE_RULES.manifestDigest, signature: 'verified', reason: null, refusal: null },
                    // Not a failure (decision 0017): there is no Python here for it to read.
                    { pluginId: 'python-typing', state: 'not_applicable', findings: null, languages: ['python'],
                      manifestDigest: PYTHON_TYPING.manifestDigest, signature: null, reason: null, refusal: null }
                ],
                findingsTotal: 10, findingsTruncated: false,
                findings: [
                    finding(901, 'vulnerability', 'critical', 'CVE-2021-44228', {
                        description: 'Apache Log4j2 JNDI features do not protect against attacker-controlled LDAP endpoints',
                        filePath: 'pom.xml', packageName: 'log4j-core', packageVersion: '2.14.1', fixVersions: '2.17.1', tool: 'trivy',
                        link: 'https://nvd.nist.gov/vuln/detail/CVE-2021-44228' }),
                    finding(902, 'vulnerability', 'high', 'CVE-2024-38816', {
                        description: 'Path traversal in functional web frameworks',
                        filePath: 'pom.xml', packageName: 'spring-webmvc', packageVersion: '6.1.12', fixVersions: '6.1.13', tool: 'trivy' }),
                    finding(903, 'vulnerability', 'high', 'CVE-2022-25857', {
                        description: 'Denial of service through nested collections',
                        filePath: 'pom.xml', packageName: 'snakeyaml', packageVersion: '1.30', fixVersions: '1.31', tool: 'trivy' }),
                    finding(904, 'secret', 'high', 'aws-access-token', {
                        filePath: 'config/application-dev.yml', line: 14, tool: 'gitleaks' }),
                    finding(905, 'secret', 'high', 'aws-access-token', {
                        filePath: 'config/application-dev.yml', line: 31, tool: 'gitleaks' }),
                    finding(906, 'sast', 'medium', sqlString, { filePath: builder, line: 88, tool: 'opengrep' }),
                    finding(907, 'sast', 'medium', sqlString, { filePath: builder, line: 141, tool: 'opengrep' }),
                    finding(908, 'sast', 'medium', sqlString, { filePath: builder, line: 203, tool: 'opengrep' }),
                    finding(909, 'iac', 'medium', 'DS002', {
                        description: 'The image runs as root', filePath: 'Dockerfile', line: 1, tool: 'trivy' }),
                    finding(910, 'plugin', 'low', 'house-rules.no-system-exit', {
                        description: 'System.exit() outside the launcher',
                        filePath: 'src/main/java/portal/Shutdown.java', line: 27, tool: 'house-rules',
                        toolName: 'house-rules', toolVersion: '1.3.0' })
                ]
            });
            await enterApp(page, locale);
            await openScreen(page, '/dashboard');
            // Through the dashboard's recent scans, the way a reader arrives at one scan.
            await page.locator('a[href="/scans/34"]').first().click();
            await expect(page).toHaveURL(/\/scans\/34(\?|$)/, { timeout: 15_000 });

            await expect(page.getByTestId('scan-issues-count')).toHaveText('7', { timeout: 15_000 });
            await expect(page.getByTestId('scan-occurrences-count')).toContainText('10');
            await shoot(page, 'scan-detail', locale);

            // **The list beneath, one row per occurrence**, which is where seven issues become ten
            // rows: the same token on two lines, the same rule on three.
            const occurrences = page.locator('p-card').filter({ has: page.locator('p-table') }).last();
            await expect(occurrences).toContainText('LegacyQueryBuilder.java');
            await occurrences.evaluate((node) => {
                (node as HTMLElement).style.scrollMarginTop = '5rem';
                node.scrollIntoView({ block: 'start', behavior: 'instant' });
            });
            await shoot(page, 'scan-detail-occurrences', locale);
        });

        test('history', async ({ page }, testInfo) => {
            const locale = edition(testInfo.project.name);
            await stubEverything(page);
            const helios = { id: 5, name: 'helios-portal', url: 'ssh://git@example.invalid/helios-portal.git',
                             branch: 'main', lastScanAt: '2026-09-17T21:04:00Z', openIssues: 7, decisions: 2,
                             scanCount: 2, projectType: 'maven', version: '4.2.0' };
            await stub(page, '**/api/v1/history/repositories', [
                helios,
                { id: 6, name: 'basalt-libs', url: 'ssh://git@example.invalid/basalt-libs.git', branch: 'master',
                  lastScanAt: '2026-09-16T03:11:00Z', openIssues: 37, decisions: 0, scanCount: 5,
                  projectType: 'gradle', version: null }
            ]);
            const observed = (id: number, identifier: string, severity: string, pkg: string, version: string,
                              state: string, triage: string | null, decisions: unknown[] = [], resolvedAt: string | null = null) => ({
                id, identifier, severity, type: 'vulnerability', packageName: pkg, packageVersion: version,
                filePath: null, state, triageStatus: triage, firstSeenAt: '2026-08-21T07:57:53Z', resolvedAt, decisions
            });
            // The scan of the 17th, which the SBOM comparison and the scan detail show — seven
            // issues, one new, three resolved — over the one of the 10th it is compared with.
            await stub(page, '**/api/v1/history/repositories/5*', {
                generatedAt: '2026-09-18T12:00:00Z',
                repository: helios,
                scans: [
                    { id: 34, status: 'completed', branch: 'main', createdAt: '2026-09-17T21:04:00Z', durationMs: 91_000,
                      findingsCount: 7, newIssuesCount: 1, resolvedIssuesCount: 3, error: null,
                      projectType: 'maven', version: '4.2.0',
                      issues: [
                          observed(41, 'CVE-2021-44228', 'critical', 'log4j-core', '2.14.1', 'open', 'under_review', [
                              { occurredAt: '2026-09-02T09:14:00Z', fromStatus: null, toStatus: 'under_review',
                                justification: null, comment: 'Upgrade planned with the 4.3 release', actor: 'c.moreau',
                                origin: 'manual', expiresAt: null, previousResolvedAt: null, scanId: 31, version: '4.1.2' }
                          ]),
                          observed(44, 'CVE-2024-38816', 'high', 'spring-webmvc', '6.1.12', 'open', null),
                          observed(45, 'CVE-2022-25857', 'high', 'snakeyaml', '1.30', 'open', null),
                          observed(49, 'CVE-2024-22262', 'high', 'spring-web', '6.1.4', 'resolved', null, [],
                                   '2026-09-17T21:04:00Z')
                      ] },
                    { id: 33, status: 'completed', branch: 'main', createdAt: '2026-09-10T21:03:00Z', durationMs: 88_000,
                      findingsCount: 9, newIssuesCount: 0, resolvedIssuesCount: 0, error: null,
                      projectType: 'maven', version: '4.1.2', issues: [] }
                ]
            });
            await enterApp(page, locale);
            await openScreen(page, '/history');

            await expect(page.getByText('CVE-2021-44228').first()).toBeVisible({ timeout: 15_000 });
            await shoot(page, 'history', locale);
        });

        test('settings: tracker and SIEM', async ({ page }, testInfo) => {
            const locale = edition(testInfo.project.name);
            await stubEverything(page);
            // The tracker's section of the catalogue as `Setting` defines it: an internal GitLab,
            // reached through the organisation's own CA, which is pinned here and read back.
            const setting = (key: string, type: string, value: string, defaultValue: string,
                             administratorOnly = true) => ({
                key, type, section: 'Ticket tracker', label: TICKET_SETTINGS[key].label, help: TICKET_SETTINGS[key].help,
                default: defaultValue, value, configured: value !== defaultValue,
                governor_only: false, administrator_only: administratorOnly
            });
            await stub(page, '**/api/v1/settings', {
                settings: [
                    setting('ticket_provider', 'text', 'gitlab', 'none', false),
                    setting('ticket_base_url', 'text', 'https://git.example.org', ''),
                    setting('ticket_project', 'text', 'appsec/vectispire-findings', ''),
                    setting('ticket_token', 'text', '', ''),
                    setting('ticket_webhook_secret', 'text', '', ''),
                    setting('ticket_token_expires_on', 'text', '', ''),
                    setting('ticket_user', 'text', '', ''),
                    setting('ticket_issue_type', 'text', 'Bug', 'Bug', false),
                    setting('ticket_labels', 'text', 'vectispire,security', 'vectispire,security', false),
                    setting('ticket_allow_private_url', 'boolean', 'true', 'true', false),
                    setting('ticket_ca_pem', 'text', EXAMPLE_CA_PEM, '')
                ]
            });
            await stub(page, '**/api/v1/settings/ticket-ca', {
                pinned: true, subject: 'CN=Example Internal Root CA', notAfter: '2030-01-01T00:00:00Z'
            });
            // GitLab reports its tokens' expiry: eleven days ahead of the frozen clock, inside the
            // fourteen the screen warns at.
            await stub(page, '**/api/v1/settings/ticket-token', {
                configured: true, expiresAt: '2026-09-29T00:00:00Z', expirySource: 'reported',
                checkedAt: '2026-09-18T06:00:00Z', refusedSince: null, refusedStatus: null
            });
            await stub(page, '**/api/v1/settings/ticket-webhook-secret', { configured: true });
            await stub(page, '**/api/v1/settings/webhook-secret', { configured: false });
            await stub(page, '**/api/v1/siem/config', {
                enabled: true, protocol: 'SYSLOG_TLS', endpoint: 'siem.example.org:6514', hasAuthHeader: false,
                minSeverity: 'MEDIUM', tlsCaPem: EXAMPLE_CA_PEM, tlsCaSubject: 'CN=Example Internal Root CA',
                tlsCaNotAfter: '2030-01-01T00:00:00Z', updatedAt: '2026-09-02T10:00:00Z'
            });
            // Asked for by the threat-intelligence tab's component whichever tab is open, and drawn
            // on none of these captures: a synchronised feed, the ordinary state.
            await stub(page, '**/api/v1/threat-intel/status', {
                status: 'SYNCED', lastSyncedAt: '2026-09-18T03:00:00Z', lastAttemptAt: '2026-09-18T03:00:00Z',
                lastError: null, kevCatalogVersion: '2026.09.17', kevReleasedAt: '2026-09-17T18:00:00Z',
                totalKev: 1384, totalCves: 412, backlogUpdatedCount: 3,
                epss: { status: 'SYNCED', lastSyncedAt: '2026-09-18T03:05:00Z', lastAttemptAt: '2026-09-18T03:05:00Z',
                        lastError: null, modelVersion: 'v2025.03.14', scoreDate: '2026-09-17T00:00:00Z',
                        totalScored: 412, backlogUpdatedCount: 11, inProgress: false }
            });
            await enterApp(page, locale);
            // The menu's "Integrations" entry carries its tab in the query; `openScreen` matches a
            // path, so the link is clicked here and the address checked as it does.
            await page.locator('a[href="/settings?tab=integrations"]').first().click();
            await expect(page).toHaveURL(/\/settings\?tab=integrations$/, { timeout: 15_000 });

            const showFromTop = async (testId: string) =>
                page.getByTestId(testId).evaluate((node) => {
                    const card = (node.closest('p-card') ?? node) as HTMLElement;
                    card.style.scrollMarginTop = '5rem';
                    card.scrollIntoView({ block: 'start', behavior: 'instant' });
                });

            // **Aligned on the CA's foot, not on the card's top.** The French help texts make the card
            // taller than the viewport, and aligned on its title the line saying what the pinned CA
            // is — the thing this capture is for — fell below the fold in one edition only.
            await expect(page.getByTestId('ticket-ca-pinned')).toContainText('CN=Example Internal Root CA', { timeout: 15_000 });
            await page.getByTestId('ticket-ca-pinned').evaluate((node) => {
                (node as HTMLElement).style.scrollMarginBottom = '2rem';
                node.scrollIntoView({ block: 'end', behavior: 'instant' });
            });
            await shoot(page, 'settings-tickets', locale);

            await expect(page.getByTestId('ticket-token-health')).toContainText('2026-09-29');
            await showFromTop('ticket-token-health');
            await shoot(page, 'settings-ticket-token', locale);

            await expect(page.getByTestId('siem-ca-pinned')).toContainText('CN=Example Internal Root CA');
            await showFromTop('siem-ca-pinned');
            await shoot(page, 'settings-siem', locale);
        });

        test('rule catalogue import', async ({ page }, testInfo) => {
            const locale = edition(testInfo.project.name);
            await stubEverything(page);
            await stub(page, '**/api/v1/rule-sets/coverage', RULE_COVERAGE);
            await stub(page, '**/api/v1/rule-sets', { ruleSets: [] });
            // The upstream as `RuleCatalogue` names it, at one commit, with the counts a reader
            // chooses from. The licence text is abridged: the screen shows it whole, and a capture
            // of it whole would be a capture of a licence.
            await stub(page, '**/api/v1/rule-sets/catalogue', {
                upstream: 'opengrep/opengrep-rules',
                commit: 'a41c09e7d35b8f2c6e1a94b07d3f5c28e9b16a40',
                licenceName: 'LGPL-2.1 with Commons Clause',
                licence: [
                    '"Commons Clause" License Condition v1.0',
                    '',
                    'The Software is provided to you by the Licensor under the License, as defined below,',
                    'subject to the following condition. […]',
                    '',
                    'GNU LESSER GENERAL PUBLIC LICENSE — Version 2.1, February 1999 […]'
                ].join('\n'),
                licence_sha256: '5e8f2a1c7b3d9e04f6a2c8b1d5e9f3a7c0b4d8e2f6a1c5b9d3e7f0a4c8b2d6e1',
                languages: { generic: 84, java: 312, javascript: 268, python: 297, typescript: 154, yaml: 61 },
                categories: { A01: 58, A02: 41, A03: 233, A05: 66, A06: 12, A07: 29, A08: 17, A10: 9 },
                gitleaksDuplicates: 38
            });
            await enterApp(page, locale);
            await openScreen(page, '/rule-sets');

            await page.getByRole('button', { name: /read the catalogue|lire le catalogue/i }).click();
            await expect(page.locator('#lang-generic')).toBeAttached({ timeout: 15_000 });
            // Java and Python, which the estate holds, and generic — where the secret rules are,
            // so the note on the rules that duplicate gitleaks appears with its opt-out.
            for (const language of ['java', 'python', 'generic']) {
                await page.locator('p-checkbox', { has: page.locator(`#lang-${language}`) }).click();
            }
            await expect(page.getByTestId('gitleaks-duplicates')).toContainText('38', { timeout: 15_000 });
            await page.getByTestId('gitleaks-duplicates').evaluate((node) => {
                const card = node.closest('p-card') as HTMLElement | null;
                if (!card) return;
                card.style.scrollMarginTop = '5rem';
                card.scrollIntoView({ block: 'start', behavior: 'instant' });
            });
            await shoot(page, 'rule-catalogue-import', locale);
        });
    });
