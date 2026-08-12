import { DataSource } from 'typeorm';
import { PostgreSqlContainer, StartedPostgreSqlContainer } from '@testcontainers/postgresql';
import { ENTITIES } from '../src/persistence/entities';
import { Dialect, parseDialect } from '../src/persistence/dialects';

/**
 * La base des tests d'intégration, démarrée par testcontainers.
 *
 * **Ce qui a changé et pourquoi.** Chaque suite commençait par
 * `const describeWithPostgres = connectionString ? describe : describe.skip` : sans
 * `ZANSHIN_TEST_DATABASE_URL`, les douze fichiers se sautaient **en silence** et la
 * campagne rapportait vert en n'ayant rien vérifié. C'est exactement le genre de défaut
 * que ce projet existe pour trouver, et il était dans son propre harnais.
 *
 * Le conteneur est donc démarré par le harnais. Il n'y a plus rien à sauter : sans
 * Docker, les tests échouent — bruyamment, ce qui est le comportement correct.
 *
 * **Le dialecte est un paramètre.** `ZANSHIN_TEST_DIALECT` choisit le moteur, pour que la
 * même suite s'exécute contre PostgreSQL puis MySQL sans réécriture. Un défaut de
 * portabilité qui n'apparaît que sur l'un des deux ne se trouve qu'en exécutant les deux.
 *
 * **Deux registres de modules, pas un.** `globalSetup` de Jest s'exécute dans un contexte
 * séparé de celui des tests : une variable de module posée là n'est pas visible ici. Le
 * conteneur communique donc par l'environnement — la seule chose que les deux partagent —
 * et chaque processus de test ouvre sa propre source de données sur la même base.
 */

const URL_VARIABLE = 'ZANSHIN_TEST_DATABASE_URL';

export function testDialect(): Dialect {
    return parseDialect(process.env.ZANSHIN_TEST_DIALECT ?? 'postgres');
}

/**
 * Démarre le conteneur et applique les migrations. Appelé une fois par `globalSetup`.
 *
 * Les migrations plutôt que `synchronize` : c'est le schéma que la production recevra, et
 * tester contre un schéma synthétisé laisserait passer une migration incorrecte.
 */
export async function startDatabase(): Promise<{ url: string; version: string; container: StartedPostgreSqlContainer }> {
    const dialect = testDialect();
    if (dialect !== 'postgres') {
        throw new Error(
            `Le dialecte « ${dialect} » n'a pas encore de conteneur de test. Ajoutez-le ici plutôt ` +
                'que de sauter les tests : une suite qui se saute rapporte vert sans rien vérifier.'
        );
    }

    const container = await new PostgreSqlContainer('postgres:16-alpine')
        .withDatabase('zanshin')
        .withUsername('zanshin')
        .withPassword('zanshin')
        .start();

    const url = container.getConnectionUri();
    const source = new DataSource({
        type: 'postgres',
        url,
        entities: ENTITIES,
        migrations: [`${__dirname}/../src/persistence/migrations/*.ts`],
        synchronize: false
    });
    await source.initialize();
    await source.runMigrations({ transaction: 'all' });
    const [{ version }] = await source.query('SELECT version()');
    await source.destroy();

    return { url, version: String(version).split(',')[0], container };
}

let connection: DataSource | null = null;

/**
 * La source de données de *ce* processus de test, ouverte à la demande.
 *
 * Une par processus et non une par suite : ouvrir dix-huit connexions pour douze fichiers
 * épuiserait le pool du conteneur bien avant la fin de la campagne.
 */
export async function connectToTestDatabase(): Promise<DataSource> {
    if (connection?.isInitialized) return connection;

    const url = process.env[URL_VARIABLE];
    if (!url) {
        throw new Error(
            `${URL_VARIABLE} est absente : le harnais global n'a pas démarré la base. ` +
                'Lancez les tests par « npm run test:integration », qui pose le globalSetup.'
        );
    }

    connection = new DataSource({ type: 'postgres', url, entities: ENTITIES, synchronize: false });
    await connection.initialize();
    return connection;
}

export async function disconnectFromTestDatabase(): Promise<void> {
    if (connection?.isInitialized) await connection.destroy();
    connection = null;
}
