import { readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * La connexion de production et celle du harnais de test disent la même chose.
 *
 * **Ce test existe parce qu'elles divergeaient.** Le harnais posait `timezone: 'Z'` sur
 * MySQL ; l'application posait `dateStrings: true`, qui rend des chaînes là où les entités
 * déclarent des `Date`. La campagne d'intégration était verte de bout en bout — elle
 * n'exerçait que la connexion du harnais — et la production aurait relu ses horodatages
 * dans le fuseau de la machine, faisant échouer la chaîne d'audit à sa propre vérification.
 *
 * Un test qui compare deux fichiers texte est grossier, et c'est délibéré : la seule
 * alternative serait de démarrer les deux sources de données pour comparer leurs options,
 * ce qui demanderait une base. Ce qu'on veut vérifier est qu'un réglage n'a pas été posé
 * d'un côté seulement — la lecture du source suffit à le dire.
 */

const APPLICATION = join(__dirname, 'persistence.module.ts');
const HARNESS = join(__dirname, '..', '..', 'test', 'database.ts');

/** Les réglages de connexion qui changent la sémantique des données lues. */
const MUST_MATCH = [
    {
        setting: "timezone: 'Z'",
        why:
            'Sans lui, le pilote MySQL convertit les `datetime` selon le fuseau de la machine : ' +
            "une valeur écrite l'été se relit décalée d'une heure, et la chaîne d'audit se déclare falsifiée."
    }
];

describe('parité des connexions', () => {
    const application = readFileSync(APPLICATION, 'utf8');
    const harness = readFileSync(HARNESS, 'utf8');

    it.each(MUST_MATCH)('$setting est posé des deux côtés', ({ setting, why }) => {
        expect(application.includes(setting)).toBe(true);
        expect(harness.includes(setting)).toBe(true);
        expect(why.length).toBeGreaterThan(0);
    });

    it("n'utilise pas `dateStrings`, qui rendrait des chaînes là où les entités déclarent des Date", () => {
        // Le réglage qui avait été posé à la place, et dont l'effet ne se voyait qu'en
        // production : TypeORM réhydrate alors une chaîne dans un champ typé `Date`.
        expect(application).not.toContain('dateStrings');
        expect(harness).not.toContain('dateStrings');
    });
});
