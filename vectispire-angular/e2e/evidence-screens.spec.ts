import { resetLoginThrottle } from './support/fixture';
import { test, expect, Page } from '@playwright/test';
import { goTo, signIn, signInAs } from './support/session';

/**
 * The six evidence screens, in a real browser.
 *
 * <h2>What a browser adds here, said precisely</h2>
 *
 * <p>The unit specs do mount these templates, and already assert the calculations. What they
 * cannot see comes down to three things, and all three are exactly what these features lacked for
 * a week: <b>that a menu entry leads there</b> — every case navigates by clicking in the sidebar,
 * never through `page.goto` —, <b>that the role opening the page sees what it should</b>, and that
 * the page survives the full path.
 *
 * <h2>What each case chooses to assert</h2>
 *
 * <p>One number per screen, and every time <b>the one the page refuses to produce</b> rather than
 * one it displays. An absent refusal rate on zero verdicts, an absent percentage on a severity
 * with no deadline, an absent scope gap when nobody declared one: those are the three places where
 * a zero would read as good news, and the only ones an assertion of "the page renders" would let
 * through without a word.
 *
 * <p>The API is stubbed rather than seeded. What is tested is the agreement between a response and
 * what a reader sees of it; a database whose contents depend on what a scan found would make a
 * wrong page look like a data problem.
 */
test.describe('Evidence screens', () => {

    // The brute-force budget is global and narrow: see `resetLoginThrottle`.
    test.beforeEach(() => resetLoginThrottle());

    /** A JSON response for a route, without repeating the envelope each time. */
    async function stub(page: Page, pattern: string, body: unknown): Promise<void> {
        await page.route(pattern, (route) =>
            route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) }));
    }

    const EXCEPTION = {
        issue_id: 41,
        identifier: 'CVE-2026-0001',
        severity: 'critical',
        target_kind: 'REPOSITORY',
        target_id: 7,
        target_name: 'helios-portal',
        decision: 'not_affected',
        justification: 'vulnerable_code_not_in_execute_path',
        comment: null,
        actor: 'c.moreau',
        origin: 'manual',
        decided_at: '2026-01-12T09:00:00Z',
        expires_at: '2026-08-12T00:00:00Z',
        lapsed: true,
        last_reviewed_at: null,
        last_reviewed_by: null
    };

    async function stubExceptions(page: Page): Promise<void> {
        await stub(page, '**/api/v1/exceptions*', {
            entries: [EXCEPTION], granted: 1, awaiting_approval: 0, lapsed: 1, never_reviewed: 1
        });
    }

    test('the exceptions register counts what nobody has revisited', async ({ page }) => {
        await stubExceptions(page);
        await signIn(page);
        await goTo(page, '/exceptions');

        await expect(page.getByText('never revisited')).toBeVisible({ timeout: 15000 });
        // The row says it too: without that word, an exception reopened every quarter and one
        // nobody has opened since January read identically.
        await expect(page.getByText('never', { exact: true }).first()).toBeVisible();
    });

    test('a security lead is offered the review, an auditor is not', async ({ page }) => {
        await stubExceptions(page);
        await signInAs(page, 'CISO');
        await goTo(page, '/exceptions');
        await expect(page.getByRole('button', { name: 'Review' })).toBeVisible({ timeout: 15000 });

        // The same screen, the same data, another role. Confirming an exception is a claim about
        // risk somebody has to carry; an auditor reads it without signing it.
        await signInAs(page, 'AUDITOR');
        await goTo(page, '/exceptions');
        await expect(page.getByText('never revisited')).toBeVisible({ timeout: 15000 });
        await expect(page.getByRole('button', { name: 'Review' })).toHaveCount(0);
    });

    test('the verdict register shows no refusal rate when the gate has never answered', async ({ page }) => {
        await stub(page, '**/api/v1/gate/verdicts*', { verdicts: [], passed: 0, refused: 0 });
        await signIn(page);
        await goTo(page, '/gate-verdicts');

        // Scoped to the figures block, and on the absence of *any* percentage. Looking for "0 %"
        // and finding none would also pass if the page had not rendered at all.
        const figures = page.locator('.card .grid').first();
        await expect(figures).toContainText('refusal rate', { timeout: 15000 });
        // `0 %` would read as "the gate refuses nothing" where the true sentence is "the gate has
        // not answered yet". That is the confusion this whole screen exists to prevent.
        await expect(figures).not.toContainText('%');
    });

    test('time to fix leaves a severity with no deadline unmeasured', async ({ page }) => {
        await stub(page, '**/api/v1/remediation/distribution*', {
            windowDays: 90,
            oldestOpenDays: 241,
            oldestOpenSeverity: 'critical',
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
        await signIn(page);
        await goTo(page, '/remediation-delays');

        // The oldest open item is at the top of the screen: the line no mean can show and the
        // first an assessor asks for. "241 days" and not "241": the number is also in the table's
        // column, and it has to be — what this case checks is that it is *also* at the top, outside
        // the table.
        await expect(page.getByText('241 days')).toBeVisible({ timeout: 15000 });
        await expect(page.getByText('No deadline set', { exact: false })).toBeVisible();
    });

    test('the rule coverage banner speaks only when rules are missing', async ({ page }) => {
        await stub(page, '**/api/v1/rule-sets/coverage', {
            state: 'COVERED', languagesWithRules: ['java'], ecosystemsInEstate: ['maven'],
            uncovered: [], ruleFiles: 40
        });
        await stub(page, '**/api/v1/rule-sets', { ruleSets: [] });
        await signIn(page);
        await goTo(page, '/rule-sets');

        // A warning shown when all is well loses its meaning within days, and then the one that
        // matters becomes invisible too.
        await expect(page.getByText('Code analysis covers one pattern')).toHaveCount(0);

        await stub(page, '**/api/v1/rule-sets/coverage', {
            state: 'UNCONFIGURED', languagesWithRules: ['python'], ecosystemsInEstate: ['maven'],
            uncovered: ['java'], ruleFiles: 1
        });
        // **No `page.reload()` here.** Vectispire's session lives in memory rather than in a
        // cookie: a full navigation loses it and the guard sends you back to the sign-in form. So
        // we go through the sidebar again, which is a reader's path anyway.
        await goTo(page, '/issues');
        await goTo(page, '/rule-sets');
        await expect(page.getByText('Code analysis covers one pattern', { exact: false }))
            .toBeVisible({ timeout: 15000 });
    });

    test('the statement of applicability opens on its worst divergence', async ({ page }) => {
        function line(id: string, divergence: string) {
            return {
                control: { id, name: id, requirement: 'x', category: 'GOVERNANCE' },
                declaration: {
                    framework: 'ISO_27001', controlId: id, applicability: 'APPLICABLE',
                    justification: 'In scope.', implementation: 'IMPLEMENTED',
                    evidenceSource: 'VECTISPIRE', externalEvidence: null, owner: 'n.faure',
                    decidedBy: 'c.moreau', decidedAt: '2026-01-01T00:00:00Z',
                    reviewedAt: '2026-01-01T00:00:00Z', reviewDueAt: null
                },
                measured: 'NON_COMPLIANT', divergence, reviewOverdue: false
            };
        }
        await stub(page, '**/api/v1/compliance/soa', [{
            framework: 'ISO_27001', total: 2, declared: 2, findings: 1, reviewsOverdue: 0,
            complete: true,
                // The server returns the standard's order: consistent first, contradicted after.
            lines: [line('ISO-A.5.15', 'CONSISTENT'), line('ISO-A.8.8', 'CONTRADICTED')]
        }]);
        await signIn(page);
        await goTo(page, '/soa');

        await expect(page.getByText('Contradicted')).toBeVisible({ timeout: 15000 });

        // A contradicted control filed below the consistent ones is a finding nobody sees.
        const ids = await page.locator('td .font-mono').allTextContents();
        expect(ids.slice(0, 2)).toEqual(['ISO-A.8.8', 'ISO-A.5.15']);
    });

    test('the compliance progression does not paint a wider estate as regression', async ({ page }) => {
        await stub(page, '**/api/v1/compliance/history', [{
            framework: 'ISO_27001',
            comparable: false,
            steps: [
                {
                    snapshot: {
                        period: '2026-07', framework: 'ISO_27001', score: 90, status: 'PARTIAL',
                        targets: 10, observed: 10, fresh: 10, freshnessDays: 30,
                        endOfLifeEnabled: true, codeAnalysisReaches: true,
                        controlsTotal: 4, controlsDeclared: 4, soaFindings: 0,
                        capturedAt: '2026-07-31T00:00:00Z'
                    },
                    delta: 0, movement: 'FIRST', because: 'First capture for this framework.'
                },
                {
                    snapshot: {
                        period: '2026-08', framework: 'ISO_27001', score: 71, status: 'PARTIAL',
                        targets: 14, observed: 14, fresh: 14, freshnessDays: 30,
                        endOfLifeEnabled: true, codeAnalysisReaches: true,
                        controlsTotal: 4, controlsDeclared: 4, soaFindings: 0,
                        capturedAt: '2026-08-31T00:00:00Z'
                    },
                    delta: -19, movement: 'ESTATE_GREW',
                    because: '4 target(s) more than last month. A score that falls here is the cost of watching wider, not a regression.'
                }
            ]
        }]);
        await signIn(page);
        await goTo(page, '/compliance-history');

        // Nineteen points lost, and the reason is on screen rather than left to the interpretation
        // of a line going down.
        await expect(page.getByText('-19')).toBeVisible({ timeout: 15000 });
        await expect(page.getByText('not a regression', { exact: false })).toBeVisible();

        // Without that note, two joined points read as a trajectory whatever the distance between
        // the two estates that produced them.
        await expect(page.getByText('this is a shape, not a trend', { exact: false })).toBeVisible();
    });

    test('the certified scope reports an undeclared scope as undeclared, not as complete', async ({ page }) => {
        await stub(page, '**/api/v1/compliance/scope', {
            statement: '',
            coverage: { declaredAssets: 0, inScope: 3, scannedRecently: 3, stale: 0, neverScanned: 0 },
            targets: []
        });
        await stub(page, '**/api/v1/repositories', []);
        await stub(page, '**/api/v1/containers', []);
        await signIn(page);
        await goTo(page, '/certified-scope');

        // Three targets in scope, three scanned recently: without the declared count, any tool
        // measuring its own coverage announces one hundred per cent.
        await expect(page.getByText('undeclared')).toBeVisible({ timeout: 15000 });
        // The whole sentence and not its ending: "carries current evidence" is also in the
        // screen's subtitle, and the assertion was failing on the page that is right.
        await expect(page.getByText('of the declared scope')).toHaveCount(0);
    });
});
