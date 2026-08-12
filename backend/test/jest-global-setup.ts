import { startDatabase } from './database';

/**
 * Démarre la base une fois pour toute la campagne, et non par fichier de test.
 *
 * Un conteneur par fichier coûterait une dizaine de secondes chacun ; un seul conteneur
 * partagé impose en retour que chaque test s'isole dans une transaction annulée, ce que
 * les suites font déjà.
 *
 * L'URL passe par l'environnement : `globalSetup` et les tests vivent dans deux registres
 * de modules distincts, et c'est la seule chose qu'ils partagent. Le conteneur, lui, est
 * confié à `globalThis`, que `globalTeardown` retrouve — il tourne dans le même contexte.
 */
export default async function globalSetup(): Promise<void> {
    const started = Date.now();
    const { url, version, container } = await startDatabase();

    process.env.ZANSHIN_TEST_DATABASE_URL = url;
    (globalThis as Record<string, unknown>).__ZANSHIN_TEST_CONTAINER__ = container;

    console.log(`\nBase de test prête en ${Math.round((Date.now() - started) / 100) / 10} s — ${version}`);
}
