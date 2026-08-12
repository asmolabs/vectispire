import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

/**
 * La convention de nommage du schéma, vérifiée plutôt que documentée.
 *
 * **Toutes les tables portent le préfixe `t_`.** Cela écarte d'un coup les collisions
 * avec les mots réservés : `user` en est un en PostgreSQL, où `FROM user` désigne la
 * fonction courante et non la table, et `session`, `order` ou `group` le sont selon les
 * moteurs. Préfixer vaut mieux que renommer au cas par cas, parce qu'on ne peut pas
 * oublier de le faire.
 *
 * Et « on ne peut pas oublier » n'est vrai que si quelque chose le vérifie : une
 * convention écrite dans un commentaire est une convention qu'une table ajoutée dans deux
 * ans ne respectera pas.
 */
describe('nommage des tables', () => {
    const directory = __dirname;
    const files = readdirSync(directory).filter((name) => name.endsWith('.entity.ts'));

    it('trouve les entités', () => {
        expect(files.length).toBeGreaterThan(10);
    });

    it.each(files)('%s déclare une table préfixée par t_', (file) => {
        const source = readFileSync(join(directory, file), 'utf8');
        const declarations = [...source.matchAll(/@Entity\('([^']+)'\)/g)].map((match) => match[1]);

        expect(declarations.length).toBeGreaterThan(0);
        for (const table of declarations) {
            expect(table).toMatch(/^t_[a-z][a-z0-9_]*$/);
        }
    });

    it('n’utilise pas deux fois le même nom de table', () => {
        const declarations = files.flatMap((file) =>
            [...readFileSync(join(directory, file), 'utf8').matchAll(/@Entity\('([^']+)'\)/g)].map((match) => match[1])
        );
        expect(new Set(declarations).size).toBe(declarations.length);
    });
});
