import { containerDisplayName, repositoryDisplayName, shortRepositoryName } from './display-name';

describe('nom affiché d’une cible', () => {
    it.each([
        ['https://github.com/org/projet.git', 'org/projet'],
        ['https://github.com/org/projet', 'org/projet'],
        ['git@github.com:org/projet.git', 'org/projet'],
        ['ssh://git@gitlab.interne/equipe/sous-groupe/projet.git', 'sous-groupe/projet'],
        ['git@gitlab.interne:equipe/legacy.git', 'equipe/legacy']
    ])('abrège %s en %s', (url, expected) => {
        expect(shortRepositoryName(url)).toBe(expected);
    });

    it("préfère le nom donné par l'opérateur", () => {
        expect(repositoryDisplayName({ name: 'Legacy interne', url: 'git@x:y/z.git' })).toBe('Legacy interne');
    });

    it('retombe sur la forme courte quand aucun nom n’est donné', () => {
        // Le défaut corrigé : le tableau de bord affichait l'URL entière tandis que
        // l'écran Dépôts l'abrégeait, pour le même dépôt.
        expect(repositoryDisplayName({ name: null, url: 'https://github.com/org/frontend.git' })).toBe('org/frontend');
        expect(repositoryDisplayName({ name: '   ', url: 'https://github.com/org/frontend.git' })).toBe('org/frontend');
    });

    it('nomme un conteneur par sa référence', () => {
        expect(containerDisplayName({ imageName: 'equipe/service', tag: 'v2.1.0' })).toBe('equipe/service:v2.1.0');
    });
});
