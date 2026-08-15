import { Logger, Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule, TypeOrmModuleOptions } from '@nestjs/typeorm';
import { ENTITIES } from './entities';
import { Dialect, driverType, parseDialect, warningsFor } from './dialects';

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
            type: driverType(dialect),
            // Chemin absolu attendu : un chemin relatif donne trois bases différentes selon
            // le répertoire d'où le processus a été lancé, et l'opérateur découvre le
            // problème sous la forme d'une base vide plutôt que d'une erreur.
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
        // **UTC, explicitement — et c'est la connexion de production.**
        //
        // Le pilote MySQL convertit les `datetime` selon le fuseau de la machine : une
        // valeur écrite l'été se relit décalée d'une heure, et la chaîne d'intégrité du
        // journal d'audit — qui hache l'horodatage sérialisé — échoue alors à sa propre
        // vérification. Le journal se déclarerait falsifié sans que rien ne l'ait été.
        //
        // Ce réglage doit rester identique à celui du harnais de test (`test/database.ts`) :
        // une campagne verte contre une connexion en UTC ne dirait rien d'une production
        // qui n'y est pas. La précision, elle, est portée par le schéma — `datetime(6)`,
        // déclaré une seule fois dans `column-types.ts`.
        timezone: 'Z'
    };
}
