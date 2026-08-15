import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DataSource } from 'typeorm';
import { PostgreSqlContainer } from '@testcontainers/postgresql';
import { MySqlContainer } from '@testcontainers/mysql';
import { MariaDbContainer } from '@testcontainers/mariadb';
import type { StartedTestContainer } from 'testcontainers';
import { ENTITIES } from '../src/persistence/entities';
import { Dialect, driverType, migrationDirectory, parseDialect } from '../src/persistence/dialects';
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
export async function startDatabase(): Promise<{ url: string; version: string; container: StartedTestContainer | null }> {
    const dialect = testDialect();
    const { url, container } = await startEngine(dialect);

    const source = new DataSource({ ...connectionOptions(dialect, url), migrations: [migrationGlob(dialect)] } as never);
    await source.initialize();
    // **Pas de `transaction: 'all'` sous SQLite** : sa migration de référence recrée des
    // tables pour poser les clés étrangères — SQLite ne sait pas les ajouter après coup — et
    // ces recréations veulent gérer leurs propres transactions.
    await source.runMigrations(dialect === 'sqlite' ? undefined : { transaction: 'all' });
    const [row] = await source.query(VERSION_QUERY[dialect === 'sqlite' ? 'sqlite' : isMySql(dialect) ? 'mysql' : 'postgres']);
    await source.destroy();

    return { url, version: String(row.version).split(',')[0], container };
}

const VERSION_QUERY = {
    postgres: 'SELECT version()',
    mysql: 'SELECT VERSION() AS version',
    sqlite: 'SELECT sqlite_version() AS version'
} as const;

function migrationGlob(dialect: Dialect): string {
    return `${__dirname}/../src/persistence/migrations/${migrationDirectory(dialect)}/*.ts`;
}

/**
 * Les options de connexion du dialecte — **partagées entre le démarrage et les tests**.
 *
 * Deux constructions séparées avaient déjà divergé une fois : le harnais posait
 * `timezone: 'Z'` que la production n'avait pas, si bien que la campagne était verte contre
 * une connexion que personne n'utilisait. Une seule fonction ne peut pas se contredire.
 */
function connectionOptions(dialect: Dialect, url: string): Record<string, unknown> {
    if (dialect === 'sqlite') {
        return { type: driverType(dialect), database: url, entities: ENTITIES, synchronize: false };
    }
    return {
        type: driverType(dialect),
        url,
        ...(isMySql(dialect) ? { timezone: 'Z' } : {}),
        entities: ENTITIES,
        synchronize: false
    };
}

async function startEngine(dialect: Dialect): Promise<{ url: string; container: StartedTestContainer | null }> {
    if (dialect === 'sqlite') return startSqlite();
    if (dialect === 'mariadb') return startMariaDb();
    return dialect === 'mysql' ? startMySql() : startPostgres();
}

/**
 * SQLite : un fichier temporaire, et **aucun conteneur**.
 *
 * En mémoire aurait été plus rapide et faux : chaque connexion à `:memory:` ouvre sa propre
 * base, si bien que le processus qui applique les migrations et celui qui les exerce ne
 * verraient pas la même — la campagne serait verte sur un schéma vide. Un fichier est ce
 * qu'un opérateur déploie, et c'est ce qu'il faut éprouver.
 */
function startSqlite(): { url: string; container: null } {
    const directory = mkdtempSync(join(tmpdir(), 'zanshin-sqlite-'));
    return { url: join(directory, 'zanshin.sqlite'), container: null };
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

/**
 * MariaDB, éprouvé pour de bon.
 *
 * Ses capacités étaient **héritées de MySQL par prudence, pas par constat** — leur propre
 * commentaire le disait. Or c'est exactement la forme d'affirmation que ce dépôt s'interdit :
 * annoncer un moteur pris en charge sans l'avoir fait tourner revient à demander à un
 * opérateur de découvrir l'écart en production.
 *
 * La 11.4 est la version de maintenance longue durée, et la première à porter
 * `SKIP LOCKED` — dont la réclamation dépend.
 */
async function startMariaDb() {
    const container = await new MariaDbContainer('mariadb:11.4')
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
        ...connectionOptions(dialect, url),
        // **Plus large que le défaut de dix.** Le test de concurrence de la file ouvre dix
        // transactions simultanées pour vérifier que `SKIP LOCKED` les laisse avancer ; au
        // défaut, la dixième attend une connexion libre et le test expire — un échec qui
        // ressemble à un blocage de la base alors que c'est le pool du client qui manque.
        // SQLite n'a pas de pool : un seul écrivain, ce que ses capacités déclarent.
        ...(dialect === 'sqlite' ? {} : { extra: { max: 30 } })
    } as never);
    await connection.initialize();
    return connection;
}

export async function disconnectFromTestDatabase(): Promise<void> {
    if (connection?.isInitialized) await connection.destroy();
    connection = null;
}
