import { resetLoginThrottle } from './support/fixture';
import { test, expect } from '@playwright/test';
import { goTo, signIn } from './support/session';

test.describe('Settings Administration & Audit Log E2E', () => {

    // Le budget anti-force-brute est global et étroit : sans cela, le cas qui reçoit
    // le 429 n'est pas celui qui l'a dépensé. Voir `resetLoginThrottle`.
    test.beforeEach(() => resetLoginThrottle());

    test.beforeEach(async ({ page }) => {
        await signIn(page);
    });

    test('la double validation est visible dans les réglages, et son nom est lisible', async ({ page }) => {
        // **Ce cas s'appelait « toggles Four-Eyes Approval » et ne basculait rien** : il naviguait
        // et vérifiait qu'un `body` était visible — ce qu'un écran d'erreur 403 a aussi, et une
        // redirection de garde également. Il ne pouvait pas échouer. Le commentaire du cas voisin
        // dénonce exactement ce défaut, corrigé là et laissé ici.
        await goTo(page, '/settings');

        // **Sous « Governance », et il a fallu créer l'onglet.** La règle n'était sur aucun :
        // `isSectionVisible` était une liste blanche par onglet terminée par un `return false`, et
        // trois sections — dont celle-ci et la visibilité des cibles — ne s'affichaient nulle
        // part. Ce cas cherchait donc un libellé qu'aucun écran ne rendait.
        await page.getByRole('button', { name: /governance|gouvernance/i }).click();
        await expect(page.getByText(/double validation|four.eyes/i).first())
            .toBeVisible({ timeout: 15000 });
    });

    test('verifies audit log entries in Audit Trail page', async ({ page }) => {
        // `/audit` does not exist — the route is `/audit-log`. The case this replaced navigated
        // to the missing path and asserted a `body` was visible, which a not-found page has.
        await goTo(page, '/audit-log');
        // Une assertion sur le contenu et non sur l'existence d'un `body` : la page d'erreur en a
        // un, la page introuvable aussi.
        await expect(page.getByRole('heading', { name: /journal|audit/i }).first())
            .toBeVisible({ timeout: 15000 });
    });

});
