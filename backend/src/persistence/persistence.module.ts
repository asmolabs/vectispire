import { Logger, Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule, TypeOrmModuleOptions } from '@nestjs/typeorm';
import { ENTITIES } from './entities';
import { Dialect, parseDialect, warningsFor } from './dialects';

/**
 * La connexion à la base.
 *
 * **`synchronize` est à `false`, et ce n'est pas négociable tant que les deux plans de
 * contrôle coexistent.** Le schéma appartient aux quinze révisions Alembic ; ces
 * entités le *décrivent*. Laisser TypeORM le modifier ferait diverger les deux
 * applications sur la base qu'elles partagent, ce qui est la pire panne possible d'une
 * migration progressive. `schema-parity.integration-spec.ts` vérifie que la
 * description reste exacte.
 *
 * Le dialecte est configurable — PostgreSQL, SQLite, MySQL, MariaDB — mais les
 * limites de chacun sont **annoncées au démarrage** plutôt que découvertes en
 * production (voir `dialects.ts`). Un opérateur qui choisit MySQL doit apprendre tout
 * de suite que son journal d'audit se déclarera falsifié, pas six mois plus tard.
 */
@Module({
    imports: [
        TypeOrmModule.forRootAsync({
            imports: [ConfigModule],
            inject: [ConfigService],
            useFactory: (config: ConfigService): TypeOrmModuleOptions => {
                const logger = new Logger('Persistence');
                const dialect = parseDialect(config.get<string>('ZANSHIN_DB_DIALECT', 'postgres'));

                for (const warning of warningsFor(dialect)) {
                    logger.warn(warning.message);
                }

                if (dialect === 'postgres') {
                    // À faire avant la première connexion : sans cela, le pilote rend
                    // un `Date` pour un `timestamp`, ce qui perd la microseconde et
                    // applique le fuseau de la machine.
                }

                return { ...connectionFor(dialect, config), entities: ENTITIES, synchronize: false };
            }
        }),
        TypeOrmModule.forFeature(ENTITIES)
    ],
    exports: [TypeOrmModule]
})
export class PersistenceModule {}

function connectionFor(dialect: Dialect, config: ConfigService): TypeOrmModuleOptions {
    if (dialect === 'sqlite') {
        return {
            type: 'sqlite',
            // Chemin absolu attendu : un chemin relatif donne trois bases différentes
            // selon le répertoire d'où le processus a été lancé — le défaut que
            // `resolve_database_url()` corrige déjà côté Python.
            database: config.get<string>('ZANSHIN_DB_PATH', 'zanshin.sqlite')
        };
    }

    const url = config.get<string>('ZANSHIN_DATABASE_URL');
    if (!url) {
        throw new Error(`ZANSHIN_DATABASE_URL est requis pour le dialecte « ${dialect} ».`);
    }

    if (dialect === 'postgres') {
        return { type: 'postgres', url };
    }
    return {
        type: dialect,
        url,
        // `DATETIME(6)` sur chaque colonne de date est la seule parade à la troncature
        // à la seconde, qui casserait la chaîne d'intégrité du journal d'audit. Elle
        // doit être portée par le schéma lui-même ; ce réglage ne fait que demander au
        // pilote de ne pas réduire la précision qu'il reçoit.
        dateStrings: true
    };
}
