import type { StartedPostgreSqlContainer } from '@testcontainers/postgresql';

export default async function globalTeardown(): Promise<void> {
    const container = (globalThis as Record<string, unknown>).__ZANSHIN_TEST_CONTAINER__ as StartedPostgreSqlContainer | undefined;
    // Testcontainers arrête aussi ses conteneurs par son propre garde-fou au cas où le
    // processus meurt sans passer ici ; l'arrêt explicite rend seulement la main plus vite.
    if (container) await container.stop();
}
