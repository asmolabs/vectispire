import { containerDisplayName, repositoryDisplayName, shortRepositoryName } from './display-name';

describe("a target's display name", () => {
    it.each([
        ['https://github.com/org/projet.git', 'org/projet'],
        ['https://github.com/org/projet', 'org/projet'],
        ['git@github.com:org/projet.git', 'org/projet'],
        ['ssh://git@gitlab.interne/equipe/sous-groupe/projet.git', 'sous-groupe/projet'],
        ['git@gitlab.interne:equipe/legacy.git', 'equipe/legacy']
    ])('shortens %s to %s', (url, expected) => {
        expect(shortRepositoryName(url)).toBe(expected);
    });

    it("prefers the name the operator gave", () => {
        expect(repositoryDisplayName({ name: 'Legacy interne', url: 'git@x:y/z.git' })).toBe('Legacy interne');
    });

    it('falls back to the short form when no name is given', () => {
        // The defect this fixed: the dashboard showed the whole URL while the Repositories
        // screen shortened it, for the same repository.
        expect(repositoryDisplayName({ name: null, url: 'https://github.com/org/frontend.git' })).toBe('org/frontend');
        expect(repositoryDisplayName({ name: '   ', url: 'https://github.com/org/frontend.git' })).toBe('org/frontend');
    });

    it('names a container by its reference', () => {
        expect(containerDisplayName({ imageName: 'equipe/service', tag: 'v2.1.0' })).toBe('equipe/service:v2.1.0');
    });
});
