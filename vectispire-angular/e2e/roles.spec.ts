import { test, expect, type Page } from '@playwright/test';
import { goTo, signIn, signInAs, TRIAGE_BUTTON } from './support/session';
import { resetLoginThrottle, seedOneIssue } from './support/fixture';

/**
 * Ce que chaque rôle voit, dans un vrai navigateur.
 *
 * <p><b>Trois écrans et un flux ont été livrés sans qu'aucun navigateur ne les regarde.</b> Les
 * specs unitaires couvrent les composants, la suite navigateur ne connaissait ni `/attestation`,
 * ni `/forbidden`, ni le rôle auditeur — et un défaut y a survécu quatre jours : le bouton de
 * triage par ligne n'était pas gardé, alors que le bouton groupé l'était.
 *
 * <p>Ces cas parlent au vrai serveur, sans simuler l'API : ce qui est éprouvé ici est l'accord
 * entre ce que la route autorise et ce que l'écran propose. Les suites de triage simulent, et
 * c'est ce qui leur a permis de passer pendant que l'interface disait autre chose.
 */
// **En série.** Les cas se partagent la provision des comptes : lancés en parallèle, deux d'entre
// eux créent le même compte et le perdant reçoit un refus. Ils partagent aussi le compteur de
// tentatives de connexion, que le serveur compte par adresse.
test.describe.configure({ mode: 'serial' });


/**
 * Attend que la liste ait vraiment des lignes, et pas seulement un tableau à l'écran.
 *
 * <p><b>Une table visible n'est pas une table chargée.</b> Le composant s'affiche avec son en-tête
 * pendant que la requête part ; `count()` ne réessaie pas, contrairement à `expect`, et renvoyait
 * donc zéro bouton parce qu'il n'y avait encore aucune ligne — un « le rôle ne le voit pas » qui
 * ne parlait que de latence.
 */
async function listed(page: Page): Promise<void> {
    await expect(page.getByRole('link', { name: 'CVE-2021-44228' })).toBeVisible({ timeout: 15_000 });
}

test.describe('ce que les rôles voient', () => {

    // Le budget anti-force-brute est global et étroit : sans cela, le cas qui reçoit
    // le 429 n'est pas celui qui l'a dépensé. Voir `resetLoginThrottle`.
    test.beforeEach(() => resetLoginThrottle());

    // Une vulnérabilité, sans quoi la liste est vide et « aucun bouton de triage » est vrai pour
    // tout le monde, gardes comprises.
    test.beforeAll(() => seedOneIssue());

    test("un auditeur atteint l'attestation, et la chaîne d'audit y est jugée", async ({ page }) => {
        await signInAs(page, 'AUDITOR');
        await goTo(page, '/attestation');

        // La chaîne d'abord : c'est la seule affirmation de cette page qui se démontre.
        await expect(page.getByText(/Audit chain (intact|broken)/)).toBeVisible({ timeout: 15000 });
        await expect(page).toHaveURL(/\/attestation/);
    });

    test('un auditeur ne se voit proposer aucun triage, là où un responsable en voit', async ({ page, browser }) => {
        // **Le défaut que ce cas aurait attrapé.** Le bouton par ligne n'était pas gardé : il
        // s'affichait, ouvrait la boîte, et l'enregistrement récoltait un 403 — l'écran cassé que
        // les gardes de route venaient de supprimer partout ailleurs.
        //
        // **Les deux rôles sont dans le même cas, et c'est délibéré.** Une assertion à zéro ne
        // vaut que si le même sélecteur, sur le même écran, trouve quelque chose pour quelqu'un.
        // Séparés, le témoin positif se supprime un jour sans que rien ne devienne rouge, et il
        // ne reste qu'une assertion qui passe parce qu'elle ne cherche rien.
        await signInAs(page, 'CISO');
        await goTo(page, '/issues');
        await listed(page);
        await expect(page.getByRole('button', { name: TRIAGE_BUTTON }),
            'le triage doit être proposé à un responsable sécurité').not.toHaveCount(0);

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
        // **Ce que ce cas a appris en échouant.** Il cherchait à vérifier l'écran de refus en
        // faisant cliquer un compte ordinaire sur « Settings » — le lien n'existe pas pour lui.
        // Le menu reflète les gardes de route une à une (`isSecurityLead` pour les réglages,
        // `canReadGovernance` pour la posture, `isAdmin` pour l'administration), si bien que
        // `/forbidden` n'est atteignable par aucun clic : c'est un filet, et le filet est vide
        // parce que le plancher tient. C'est donc le plancher qu'il faut éprouver.
        await signInAs(page, 'USER');

        // Aucun des chemins gardés ne lui est proposé. Le sélecteur vise l'attribut `href`, et non
        // un libellé, pour que la vérification survive à une traduction.
        for (const path of ['/settings', '/users', '/teams', '/api-keys', '/agents',
                            '/ssh-keys', '/audit-log', '/gate-policies', '/rule-sets',
                            '/attestation']) {
            await expect(page.locator(`a[href="${path}"]`), `${path} ne doit pas être proposé`)
                .toHaveCount(0);
        }

        // Et il en reste un vrai produit : la liste des vulnérabilités s'ouvre pour lui.
        //
        // Elle est vide, et c'est juste : `target_visibility` vaut `assigned`, le compte n'est
        // dans aucune équipe, et le dépôt d'amorçage non plus. Ce que ce cas affirme est qu'il
        // atteint l'écran — pas un refus, pas l'écran de connexion — et non ce qu'il y trouve,
        // qui est le sujet du cadrage par équipe.
        await goTo(page, '/issues');
        await expect(page.locator('p-table').first()).toBeVisible({ timeout: 15_000 });
        await expect(page).toHaveURL(/\/issues/);
    });

    test("le plan de remédiation nomme une action, et non un constat", async ({ page }) => {
        // **Le calcul existait, l'écran n'existait pas.** `/api/v1/remediation/high-impact-fixes`
        // classait les mises à jour par levier et `getHighImpactFixes` attendait dans le service
        // front sans qu'aucun composant ne l'appelle. Ce cas est le premier à traverser la chaîne
        // entière, du constat en base jusqu'à la phrase que quelqu'un lira lundi matin.
        await signInAs(page, 'CISO');
        await goTo(page, '/remediation');

        // Le constat d'amorçage est un log4j-core 2.14.1 corrigé en 2.17.1 : la page doit nommer
        // le paquet **et** la version d'arrivée. Nommer le paquet seul serait la liste des
        // vulnérabilités avec un autre titre.
        await expect(page.getByText('log4j-core').first()).toBeVisible({ timeout: 15_000 });
        await expect(page.getByText('2.17.1').first()).toBeVisible();

        // Et jamais le texte de remplacement que le serveur renvoyait pour tout le monde.
        await expect(page.getByText('latest-patch')).toHaveCount(0);
    });

    test("le compte d'amorçage gouverne et n'agit pas", async ({ page }) => {
        // La décision du 2 septembre, vue de l'écran : SUPERUSER peut lever la règle de la double
        // validation, donc il ne peut pas agir sous elle. Sans cette séparation, éteindre le
        // contrôle et régler seul restait possible.
        await signIn(page);
        await goTo(page, '/issues');
        await listed(page);

        await expect(page.getByRole('button', { name: TRIAGE_BUTTON })).toHaveCount(0);
    });
});
