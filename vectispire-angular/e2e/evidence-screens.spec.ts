import { resetLoginThrottle } from './support/fixture';
import { test, expect, Page } from '@playwright/test';
import { goTo, signIn, signInAs } from './support/session';

/**
 * Les six écrans de preuve, dans un vrai navigateur.
 *
 * <h2>Ce qu'un navigateur ajoute ici, dit précisément</h2>
 *
 * <p>Les specs unitaires montent bien ces gabarits, et assertent déjà les calculs. Ce qu'elles ne
 * peuvent pas voir tient en trois choses, et les trois sont exactement ce qui a manqué à ces
 * fonctionnalités pendant une semaine : <b>qu'une entrée de menu y mène</b> — chaque cas navigue
 * en cliquant dans la barre latérale, jamais par `page.goto` —, <b>que le rôle qui ouvre la page
 * y voie ce qu'il doit</b>, et que la page survive au chemin complet.
 *
 * <h2>Ce que chaque cas choisit d'asserter</h2>
 *
 * <p>Un seul chiffre par écran, et à chaque fois <b>celui que la page refuse de produire</b>
 * plutôt qu'un chiffre qu'elle affiche. Un taux de refus absent sur zéro verdict, un pourcentage
 * absent sur une gravité sans délai, un écart de périmètre absent quand personne n'a déclaré : ce
 * sont les trois endroits où un zéro se lirait comme une bonne nouvelle, et les seuls qu'une
 * assertion « la page s'affiche » laisserait passer sans un mot.
 *
 * <p>L'API est simulée plutôt qu'alimentée. Ce qui est éprouvé est l'accord entre une réponse et
 * ce qu'un lecteur en voit ; une base dont le contenu dépend de ce qu'un scan a trouvé ferait
 * passer une page fausse pour un problème de données.
 */
test.describe('Evidence screens', () => {

    // Le budget anti-force-brute est global et étroit : voir `resetLoginThrottle`.
    test.beforeEach(() => resetLoginThrottle());

    /** Une réponse JSON pour une route, sans avoir à répéter l'enveloppe. */
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
        target_name: 'portail-client',
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
        // La ligne elle-même le dit aussi : sans ce mot, une exception rouverte chaque trimestre
        // et une que personne n'a ouverte depuis janvier se lisent à l'identique.
        await expect(page.getByText('never', { exact: true }).first()).toBeVisible();
    });

    test('a security lead is offered the review, an auditor is not', async ({ page }) => {
        await stubExceptions(page);
        await signInAs(page, 'CISO');
        await goTo(page, '/exceptions');
        await expect(page.getByRole('button', { name: 'Review' })).toBeVisible({ timeout: 15000 });

        // Le même écran, le même jeu de données, un autre rôle. Confirmer une exception est une
        // affirmation sur le risque que quelqu'un doit porter ; un auditeur la lit sans la signer.
        await signInAs(page, 'AUDITOR');
        await goTo(page, '/exceptions');
        await expect(page.getByText('never revisited')).toBeVisible({ timeout: 15000 });
        await expect(page.getByRole('button', { name: 'Review' })).toHaveCount(0);
    });

    test('the verdict register shows no refusal rate when the gate has never answered', async ({ page }) => {
        await stub(page, '**/api/v1/gate/verdicts*', { verdicts: [], passed: 0, refused: 0 });
        await signIn(page);
        await goTo(page, '/gate-verdicts');

        // Borné au bloc de chiffres, et sur l'absence de *tout* pourcentage. Chercher « 0 % » et
        // n'en trouver aucun passerait aussi si la page ne s'était pas affichée du tout.
        const figures = page.locator('.card .grid').first();
        await expect(figures).toContainText('refusal rate', { timeout: 15000 });
        // `0 %` se lirait « la barrière ne refuse rien » là où la phrase vraie est « la barrière
        // n'a pas encore répondu ». C'est la confusion que tout cet écran existe pour empêcher.
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

        // Le plus ancien élément ouvert est en haut de l'écran : c'est la ligne qu'aucune moyenne
        // ne peut montrer et la première qu'un évaluateur demande. « 241 days » et non « 241 » :
        // le chiffre est aussi dans la colonne du tableau, et il faut bien qu'il y soit — ce que
        // ce cas vérifie est qu'il est *aussi* en tête, hors du tableau.
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

        // Un avertissement affiché quand tout va bien perd son sens en quelques jours, et alors
        // celui qui compte devient invisible aussi.
        await expect(page.getByText('Code analysis covers one pattern')).toHaveCount(0);

        await stub(page, '**/api/v1/rule-sets/coverage', {
            state: 'UNCONFIGURED', languagesWithRules: ['python'], ecosystemsInEstate: ['maven'],
            uncovered: ['java'], ruleFiles: 1
        });
        // **Pas de `page.reload()` ici.** La session de Vectispire vit en mémoire et non dans un
        // cookie : une navigation complète la perd et la garde renvoie au formulaire de connexion.
        // On repasse donc par la barre latérale, qui est de toute façon le chemin d'un lecteur.
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
            // Le serveur rend l'ordre du standard : cohérent d'abord, contredit ensuite.
            lines: [line('ISO-A.5.15', 'CONSISTENT'), line('ISO-A.8.8', 'CONTRADICTED')]
        }]);
        await signIn(page);
        await goTo(page, '/soa');

        await expect(page.getByText('Contradicted')).toBeVisible({ timeout: 15000 });

        // Un contrôle contredit rangé sous les cohérents est un constat que personne ne voit.
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

        // Dix-neuf points perdus, et la raison est à l'écran plutôt que laissée à l'interprétation
        // d'une courbe qui descend.
        await expect(page.getByText('-19')).toBeVisible({ timeout: 15000 });
        await expect(page.getByText('not a regression', { exact: false })).toBeVisible();

        // Sans cette mention, deux points reliés se lisent comme une trajectoire quelle que soit
        // la distance entre les deux parcs qui les ont produits.
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

        // Trois cibles dans le périmètre, trois scannées récemment : sans le nombre déclaré, tout
        // outil qui mesure sa propre couverture annonce cent pour cent.
        await expect(page.getByText('undeclared')).toBeVisible({ timeout: 15000 });
        // La phrase entière et non sa fin : « carries current evidence » est aussi dans le
        // sous-titre de l'écran, et l'assertion échouait sur la page qui a raison.
        await expect(page.getByText('of the declared scope')).toHaveCount(0);
    });
});
