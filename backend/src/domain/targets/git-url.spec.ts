import { validateRepositoryUrl } from './git-url';

/**
 * This is not input validation: the URL lands in a `git clone` run by
 * un agent. Les cas de refus comptent donc davantage que les cas d'acceptation.
 */
describe('repository URL', () => {
    it.each([
        ['https://github.com/org/projet.git'],
        ['ssh://git@github.com/org/projet.git'],
        ['git://exemple.be/projet.git'],
        ['git@github.com:org/projet.git'],
        ['git@gitlab.interne:equipe/sous-groupe/projet.git']
    ])('accepte %s', (url) => {
        expect(validateRepositoryUrl(url)).toBeNull();
    });

    it("refuses a scheme that would give access to the agent's disk", () => {
        // `file://` clonerait un chemin local de la machine qui scanne.
        expect(validateRepositoryUrl('file:///etc/passwd')).toMatch(/is not allowed/);
    });

    it('refuses a scheme that would make git run a command', () => {
        // `ext::` makes git itself run an arbitrary command.
        expect(validateRepositoryUrl('ext::sh -c whoami')).not.toBeNull();
    });

    it.each([[''], ['pas une url'], ['https://'], ['../../etc/passwd']])('refuse %p', (url) => {
        expect(validateRepositoryUrl(url)).not.toBeNull();
    });

    it('gives a message that says what to write', () => {
        expect(validateRepositoryUrl('nawak')).toMatch(/https|ssh|git@/);
    });
});
