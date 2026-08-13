import { extractLicenses, findViolations, parseBlocklist } from './blocklist';

describe('parseBlocklist', () => {
    it('normalise et nettoie', () => {
        expect(parseBlocklist(' gpl-3.0-only , AGPL-3.0-only ,')).toEqual(new Set(['GPL-3.0-ONLY', 'AGPL-3.0-ONLY']));
    });

    it('rend un ensemble vide pour une liste absente', () => {
        expect(parseBlocklist('').size).toBe(0);
    });
});

describe('extractLicenses', () => {
    it('accepte les deux formes que Syft a employées', () => {
        // Syft a représenté les licences comme des chaînes, puis comme des objets. Ne gérer
        // qu'une forme ferait taire la règle à la prochaine montée de version — sans
        // erreur, et sans que personne ne s'en aperçoive.
        expect(extractLicenses({ licenses: ['MIT'] })).toEqual(['MIT']);
        expect(extractLicenses({ licenses: [{ value: 'MIT', spdxExpression: 'MIT' }] })).toEqual(['MIT']);
        expect(extractLicenses({ licenses: [{ spdxExpression: 'Apache-2.0' }] })).toEqual(['Apache-2.0']);
    });

    it('écarte ce qui ne porte aucune valeur', () => {
        expect(extractLicenses({ licenses: [{}, '', null, 42] as unknown[] })).toEqual([]);
        expect(extractLicenses({})).toEqual([]);
    });
});

describe('findViolations', () => {
    const sbom = {
        artifacts: [
            { name: 'lib-a', version: '1.0', purl: 'pkg:npm/lib-a@1.0', licenses: ['MIT'] },
            { name: 'lib-b', version: '2.0', purl: 'pkg:npm/lib-b@2.0', licenses: [{ value: 'GPL-3.0-only' }] }
        ]
    };

    it('signale les composants dont la licence est interdite', () => {
        const violations = findViolations(sbom, parseBlocklist('GPL-3.0-only'));

        expect(violations).toEqual([
            { license: 'GPL-3.0-only', packageName: 'lib-b', packageVersion: '2.0', purl: 'pkg:npm/lib-b@2.0' }
        ]);
    });

    it('compare sans tenir compte de la casse', () => {
        expect(findViolations(sbom, parseBlocklist('gpl-3.0-ONLY'))).toHaveLength(1);
    });

    it('ne signale rien tant qu\'aucune liste n\'est configurée', () => {
        // Quelles licences sont interdites est une décision d'organisation : un défaut
        // imposerait un jugement juridique à la place de l'opérateur.
        expect(findViolations(sbom, new Set())).toEqual([]);
    });

    it('rend une liste vide sur un SBOM illisible', () => {
        expect(findViolations({}, parseBlocklist('MIT'))).toEqual([]);
        expect(findViolations({ artifacts: 'inattendu' }, parseBlocklist('MIT'))).toEqual([]);
    });
});
