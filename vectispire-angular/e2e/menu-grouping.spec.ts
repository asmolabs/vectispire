import { resetLoginThrottle } from './support/fixture';
import { test, expect } from '@playwright/test';
import { signInAs } from './support/session';

/**
 * La barre latérale ne propose aucun lien qui mène à un refus.
 *
 * <p><b>C'est un défaut que ce produit a déjà eu</b>, sur les clés de déploiement : la route les
 * réservait à un administrateur, le menu les offrait à tout le monde, et c'était le seul moyen
 * d'atteindre `/forbidden` en cliquant. Le regroupement des écrans de preuve remet quatre routes
 * réservées à la gouvernance dans une section que tout le monde voit, donc la même erreur
 * redevient possible — d'où ce cas.
 *
 * <p>L'assertion porte dans les deux sens : un compte ordinaire ne les voit pas, et un auditeur
 * les voit. La première moitié seule passerait sur un menu qui ne les propose à personne.
 */
test.describe('Sidebar grouping', () => {

    test.beforeEach(() => resetLoginThrottle());

    /** Les quatre entrées de la section « preuves » réservées à la lecture de gouvernance. */
    const GOVERNANCE_ONLY = ['Statement of applicability', 'Certified scope', 'Verdict register', 'Audit log'];

    /** Les trois que tout compte peut ouvrir. */
    const EVERYONE = ['Compliance matrix', 'OWASP report', 'Exceptions register'];

    test('offers an ordinary account no link it would be refused', async ({ page }) => {
        await signInAs(page, 'USER');

        for (const label of EVERYONE) {
            await expect(page.getByRole('link', { name: label }), label).toHaveCount(1);
        }
        for (const label of GOVERNANCE_ONLY) {
            await expect(page.getByRole('link', { name: label }), label).toHaveCount(0);
        }
    });

    test('offers an auditor the whole evidence section', async ({ page }) => {
        // Sans cette moitié, un menu qui ne proposerait ces écrans à personne passerait le cas
        // ci-dessus — et c'est exactement la forme du défaut que ce fichier surveille.
        await signInAs(page, 'AUDITOR');

        for (const label of [...EVERYONE, ...GOVERNANCE_ONLY]) {
            await expect(page.getByRole('link', { name: label }), label).toHaveCount(1);
        }
    });
});
