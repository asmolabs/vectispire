import { resetLoginThrottle } from './support/fixture';
import { test, expect, Page } from '@playwright/test';
import { goTo, signIn } from './support/session';

/**
 * Le plan de remédiation, et l'aveu qu'il doit faire.
 *
 * <h2>Le défaut que ce cas ferme</h2>
 *
 * <p><b>Un dépôt a affiché une seule action face à des centaines de constats ouverts, et cela a
 * été lu comme une panne.</b> Le calcul était juste : le classement ne retient que les
 * vulnérabilités portant un nom de paquet, parce qu'une ligne du plan est une montée de version,
 * et le retard de ce dépôt était fait de secrets exposés — qu'on révoque, qu'on ne met pas à
 * jour. Rien à l'écran ne le disait.
 *
 * <p>Un chiffre faux se corrige, une défiance se garde. Ce que ce cas vérifie n'est donc pas un
 * chiffre mais <b>l'accord entre une réponse chargée et ce qu'un lecteur en comprend</b> : que la
 * disproportion soit nommée, et qu'elle le soit par le geste qui referme réellement la famille.
 *
 * <p>L'API est simulée : ce qui est éprouvé est cet accord, et non ce qu'un scan a trouvé.
 */
test.describe('Remediation plan', () => {

    test.beforeEach(() => resetLoginThrottle());

    async function stub(page: Page, pattern: string, body: unknown): Promise<void> {
        await page.route(pattern, (route) =>
            route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) }));
    }

    async function stubPlan(page: Page, coverage: unknown): Promise<void> {
        await stub(page, '**/api/v1/remediation/high-impact-fixes*', [{
            packageName: 'log4j-core',
            currentVersion: '2.14.1',
            recommendedVersion: '2.17.1',
            cveCountResolved: 12,
            criticalCveCount: 4,
            highCveCount: 8,
            estimatedHours: 1.3,
            leverageScore: 9.2,
            affectedCves: ['CVE-2021-44228'],
            affectedTargetNames: ['common-libs']
        }]);
        await stub(page, '**/api/v1/remediation/debt*', {
            totalOpenIssues: 412, criticalIssues: 4, highIssues: 8, mediumIssues: 0, lowIssues: 400,
            totalEstimatedHours: 812.3, totalEstimatedPersonDays: 101.5,
            vulnerabilitiesDebtHours: 12.3, secretsDebtHours: 798, sastDebtHours: 0,
            iacDebtHours: 2, licenseDebtHours: 0, eolDebtHours: 0, topHighImpactFixes: []
        });
        await stub(page, '**/api/v1/remediation/coverage*', coverage);
    }

    test('names what an upgrade cannot close, next to a plan of one line', async ({ page }) => {
        await stubPlan(page, {
            openFindings: 412,
            addressableByUpgrade: 12,
            beyondUpgrades: 400,
            gaps: [{ family: 'secret', findings: 399 }, { family: 'unpackaged', findings: 1 }]
        });
        await signIn(page);
        await goTo(page, '/remediation');

        await expect(page.getByText('What this plan cannot close')).toBeVisible({ timeout: 15000 });

        // La phrase, et non seulement les chiffres : « 12 des 412 » est ce qui fait la différence
        // entre « une action » et « une action sur douze constats, les quatre cents autres sont
        // ailleurs ».
        await expect(page.getByText('12 of the 412 open findings')).toBeVisible();

        // Et le geste, qui est le fond de l'affaire : on ne monte pas un secret de version.
        await expect(page.getByText('revoke and rotate', { exact: false })).toBeVisible();
    });

    test('says nothing when every finding closes with an upgrade', async ({ page }) => {
        // Un avertissement affiché quand tout va bien perd son sens en quelques jours, et alors
        // celui qui compte devient invisible aussi.
        await stubPlan(page, {
            openFindings: 12, addressableByUpgrade: 12, beyondUpgrades: 0, gaps: []
        });
        await signIn(page);
        await goTo(page, '/remediation');

        await expect(page.getByText('log4j-core')).toBeVisible({ timeout: 15000 });
        await expect(page.getByText('What this plan cannot close')).toHaveCount(0);
    });
});
