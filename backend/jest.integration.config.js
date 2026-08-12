/**
 * Les tests d'intégration, contre une vraie base démarrée par testcontainers.
 *
 * `--runInBand` : les suites partagent une base. En parallèle, une suite qui vide
 * `audit_log` verrait les lignes d'une autre.
 *
 * `globalSetup` démarre le conteneur et applique les migrations une fois pour la campagne.
 * Il n'y a plus de garde « sauter si la variable est absente » : une suite qui se saute
 * rapporte vert sans rien vérifier, et c'est le pire des résultats.
 */
module.exports = {
    rootDir: '.',
    testEnvironment: 'node',
    transform: { '^.+\\.ts$': ['ts-jest', { tsconfig: 'tsconfig.json' }] },
    testRegex: '.*\\.integration-spec\\.ts$',
    globalSetup: '<rootDir>/test/jest-global-setup.ts',
    globalTeardown: '<rootDir>/test/jest-global-teardown.ts',
    setupFilesAfterEnv: ['<rootDir>/test/jest-setup-after-env.ts'],
    // Démarrer un conteneur et appliquer dix-huit tables prend du temps sur une machine
    // froide ; l'échec par expiration serait un faux négatif.
    testTimeout: 60_000
};
