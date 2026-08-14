import { DataSource } from 'typeorm';
import { PostgreSqlContainer } from '@testcontainers/postgresql';
import { MySqlContainer } from '@testcontainers/mysql';
import type { StartedTestContainer } from 'testcontainers';
import { ENTITIES } from '../src/persistence/entities';
import { Dialect, parseDialect } from '../src/persistence/dialects';
import { isMySql } from '../src/persistence/column-types';

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

/**
 * Le dialecte de la campagne — **la même variable que celle des entités**.
 *
 * Il y en avait deux, `ZANSHIN_TEST_DIALECT` pour le harnais et `ZANSHIN_DB_DIALECT` pour
 * les colonnes. Deux noms pour une seule décision, et la campagne MySQL démarrait un
 * conteneur MySQL contre des entités déclarées en PostgreSQL — refusées par TypeORM avant
 * la première requête. Une seule variable ne peut pas se contredire.
 */
export function testDialect(): Dialect {
    return parseDialect(process.env.ZANSHIN_DB_DIALECT ?? 'postgres');
}

/**
 * Démarre le conteneur et applique les migrations. Appelé une fois par `globalSetup`.
 *
 * Les migrations plutôt que `synchronize` : c'est le schéma que la production recevra, et
 * tester contre un schéma synthétisé laisserait passer une migration incorrecte.
 */
export async function startDatabase(): Promise<{ url: string; version: string; container: StartedTestContainer }> {
    const dialect = testDialect();
    const { url, container } = isMySql(dialect) ? await startMySql() : await startPostgres();

    const source = new DataSource({
        type: (isMySql(dialect) ? 'mysql' : 'postgres') as never,
        url,
        entities: ENTITIES,
        // Le jeu de migrations du dialecte, jamais les deux : la référence PostgreSQL est
        // du SQL brut que MySQL refuse, et réciproquement.
        migrations: [`${__dirname}/../src/persistence/migrations/${isMySql(dialect) ? 'mysql' : 'postgres'}/*.ts`],
        synchronize: false,
        // **UTC, explicitement.** Sans cela le pilote MySQL convertit les `datetime` selon
        // le fuseau de la machine : une valeur écrite l'été se relit décalée d'une heure,
        // et la chaîne d'audit — qui hache l'horodatage sérialisé — échoue à sa propre
        // vérification. Le même piège que la pile Python avait rencontré.
        ...(isMySql(dialect) ? { timezone: 'Z' } : {})
    });
    await source.initialize();
    await source.runMigrations({ transaction: 'all' });
    const [row] = await source.query(isMySql(dialect) ? 'SELECT VERSION() AS version' : 'SELECT version()');
    await source.destroy();

    return { url, version: String(row.version).split(',')[0], container };
}

async function startPostgres() {
    const container = await new PostgreSqlContainer('postgres:16-alpine')
        .withDatabase('zanshin')
        .withUsername('zanshin')
        .withPassword('zanshin')
        .start();
    return { url: container.getConnectionUri(), container: container as unknown as StartedTestContainer };
}

/**
 * MySQL 8.4, parce que `SKIP LOCKED` n'existe que depuis la 8.
 *
 * La réclamation de scans en dépend, et une version antérieure ne rendrait pas une erreur
 * mais un comportement différent — exactement le genre de divergence que ce harnais existe
 * pour rendre visible.
 */
async function startMySql() {
    const container = await new MySqlContainer('mysql:8.4')
        .withDatabase('zanshin')
        .withUsername('zanshin')
        .withUserPassword('zanshin')
        .start();
    return { url: container.getConnectionUri(), container: container as unknown as StartedTestContainer };
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

    const dialect = testDialect();
    connection = new DataSource({
        type: (isMySql(dialect) ? 'mysql' : 'postgres') as never,
        url,
        ...(isMySql(dialect) ? { timezone: 'Z' } : {}),
        entities: ENTITIES,
        synchronize: false,
        // **Plus large que le défaut de dix.** Le test de concurrence de la file ouvre dix
        // transactions simultanées pour vérifier que `SKIP LOCKED` les laisse avancer ; au
        // défaut, la dixième attend une connexion libre et le test expire — un échec qui
        // ressemble à un blocage de la base alors que c'est le pool du client qui manque.
        extra: { max: 30 }
    });
    await connection.initialize();
    return connection;
}

export async function disconnectFromTestDatabase(): Promise<void> {
    if (connection?.isInitialized) await connection.destroy();
    connection = null;
}
