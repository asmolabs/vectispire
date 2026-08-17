import { validateRepositoryUrl } from './git-url';

/**
 * Ce n'est pas une validation de saisie : l'URL atterrit dans un `git clone` exécuté par
 * un agent. Les cas de refus comptent donc davantage que les cas d'acceptation.
 */
describe('URL de dépôt', () => {
    it.each([
        ['https://github.com/org/projet.git'],
        ['ssh://git@github.com/org/projet.git'],
        ['git://exemple.be/projet.git'],
        ['git@github.com:org/projet.git'],
        ['git@gitlab.interne:equipe/sous-groupe/projet.git']
    ])('accepte %s', (url) => {
        expect(validateRepositoryUrl(url)).toBeNull();
    });

    it('refuse un schéma qui donnerait accès au disque de l’agent', () => {
        // `file://` clonerait un chemin local de la machine qui scanne.
        expect(validateRepositoryUrl('file:///etc/passwd')).toMatch(/is not allowed/);
    });

    it('refuse un schéma qui ferait exécuter une commande par git', () => {
        // `ext::` fait exécuter une commande arbitraire par git lui-même.
        expect(validateRepositoryUrl('ext::sh -c whoami')).not.toBeNull();
    });

    it.each([[''], ['pas une url'], ['https://'], ['../../etc/passwd']])('refuse %p', (url) => {
        expect(validateRepositoryUrl(url)).not.toBeNull();
    });

    it('donne un message qui dit quoi écrire', () => {
        expect(validateRepositoryUrl('nawak')).toMatch(/https|ssh|git@/);
    });
});
