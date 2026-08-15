import 'reflect-metadata';
import { DataSource } from 'typeorm';
import { ENTITIES } from './entities';
import { driverType, migrationDirectory, parseDialect } from './dialects';

/**
 * La source de données pour l'outillage en ligne de commande — génération et exécution
 * des migrations. **Ce n'est pas celle que l'application utilise** : NestJS construit la
 * sienne dans `persistence.module.ts`, à partir de la même configuration.
 *
 * Deux sources distinctes pour la même base sont un risque de divergence, et la parade
 * est que les deux lisent les mêmes variables d'environnement et la même liste d'entités.
 */

const dialect = parseDialect(process.env.ZANSHIN_DB_DIALECT ?? 'postgres');
const url = process.env.ZANSHIN_DATABASE_URL;

const dataSource = new DataSource({
    // `as never` : l'union des pilotes ne se réduit pas au littéral que TypeORM attend dans
    // ses surcharges. Le dialecte est validé par `parseDialect`, qui est la vérification qui
    // compte.
    type: driverType(dialect) as never,
    ...(dialect === 'sqlite' ? { database: url ?? 'zanshin.sqlite' } : { url }),
    entities: ENTITIES,
    // **Un jeu de migrations par famille de moteur** — voir `migrationDirectory`.
    migrations: [`src/persistence/migrations/${migrationDirectory(dialect)}/*.ts`],
    // Jamais `true`. Le schéma appartient aux migrations : `synchronize` le ferait
    // dériver silencieusement de ce que les migrations décrivent, et la divergence
    // n'apparaîtrait qu'au déploiement suivant.
    synchronize: false,
    logging: process.env.ZANSHIN_SQL_LOGGING === 'true'
});

export default dataSource;
