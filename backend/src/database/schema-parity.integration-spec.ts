import { DataSource } from 'typeorm';
import { AuditLog } from '../audit/audit-log.entity';
import { Setting } from '../settings/setting.entity';
import { User } from '../users/user.entity';
import { configurePostgresTypeParsers } from './pg-types';

/**
 * Les entités TypeORM doivent décrire le schéma que produisent les migrations Alembic.
 *
 * **L'équivalent d'`alembic check`, et il est indispensable ici pour la même raison.**
 * Le schéma appartient à Alembic tant que les deux plans de contrôle coexistent :
 * TypeORM tourne en `synchronize: false` et *décrit* des tables existantes. Une
 * description fausse ne casse rien au démarrage — elle casse à la première requête qui
 * touche la colonne concernée, en production, sur un chemin peu emprunté.
 *
 * Ce qui est vérifié, pour chaque entité déclarée : la table existe, elle a exactement
 * les mêmes colonnes (ni oubli ni invention), et chaque colonne a le même type, la même
 * nullabilité et la même longueur.
 *
 * Ce n'est volontairement **pas** `dataSource.driver.createSchemaBuilder().log()` :
 * cette API rend les changements que TypeORM *appliquerait*, ce qui inclut des
 * différences sans conséquence (noms d'index, ordre des colonnes) et manque celles qui
 * comptent. Interroger `information_schema` dit ce qui est réellement là.
 *
 * Lancement :
 *
 *     docker run -d --name zs-pg -e POSTGRES_PASSWORD=zanshin -e POSTGRES_DB=zanshin \
 *       -p 55433:5432 postgres:16-alpine
 *     ZANSHIN_DATABASE_URL="postgresql+psycopg://postgres:zanshin@localhost:55433/zanshin" \
 *       uv run alembic upgrade head
 *     ZANSHIN_TEST_DATABASE_URL=postgres://postgres:zanshin@localhost:55433/zanshin \
 *       npm run test:integration --workspace @zanshin/backend
 */
const connectionString = process.env.ZANSHIN_TEST_DATABASE_URL;
const describeWithPostgres = connectionString ? describe : describe.skip;

/**
 * Les entités portées à ce jour. La liste grandit lot après lot ; ce test ne se
 * prononce que sur ce qu'elle contient, de sorte qu'une entité manquante soit une
 * absence assumée et non un test qui échoue par principe.
 */
const ENTITIES = [User, AuditLog, Setting];

interface ColumnShape {
    name: string;
    type: string;
    nullable: boolean;
    length: string | null;
}

describeWithPostgres('parité entre les entités TypeORM et le schéma Alembic', () => {
    let dataSource: DataSource;
    let actual: Map<string, Map<string, ColumnShape>>;

    beforeAll(async () => {
        configurePostgresTypeParsers();
        dataSource = new DataSource({ type: 'postgres', url: connectionString, entities: ENTITIES, synchronize: false });
        await dataSource.initialize();

        const rows: { table_name: string; column_name: string; data_type: string; is_nullable: string; character_maximum_length: string | null }[] = await dataSource.query(
            `SELECT table_name, column_name, data_type, is_nullable, character_maximum_length
             FROM information_schema.columns WHERE table_schema = 'public'`
        );

        actual = new Map();
        for (const row of rows) {
            if (!actual.has(row.table_name)) actual.set(row.table_name, new Map());
            actual.get(row.table_name)!.set(row.column_name, {
                name: row.column_name,
                type: row.data_type,
                nullable: row.is_nullable === 'YES',
                length: row.character_maximum_length === null ? null : String(row.character_maximum_length)
            });
        }
    }, 30_000);

    afterAll(async () => {
        if (dataSource?.isInitialized) await dataSource.destroy();
    });

    it('a bien construit le schéma depuis les migrations', () => {
        // Si la base est vide, tout ce qui suit passerait en ne vérifiant rien : c'est
        // le mode de panne d'un test de schéma, et il faut le rendre bruyant.
        expect(actual.has('alembic_version')).toBe(true);
        expect(actual.size).toBeGreaterThan(10);
    });

    describe.each(ENTITIES.map((entity) => [entity.name, entity] as const))('%s', (_name, entity) => {
        it('décrit une table qui existe', () => {
            const metadata = dataSource.getMetadata(entity);
            expect(actual.has(metadata.tableName)).toBe(true);
        });

        it('déclare exactement les colonnes de la table', () => {
            const metadata = dataSource.getMetadata(entity);
            const declared = metadata.columns.map((column) => column.databaseName).sort();
            const present = [...actual.get(metadata.tableName)!.keys()].sort();
            // Deux directions, et les deux comptent : une colonne oubliée fait perdre
            // des données en écriture, une colonne inventée fait échouer chaque SELECT.
            expect(declared).toEqual(present);
        });

        it('déclare le bon type, la bonne nullabilité et la bonne longueur', () => {
            const metadata = dataSource.getMetadata(entity);
            const table = actual.get(metadata.tableName)!;

            const mismatches: string[] = [];
            for (const column of metadata.columns) {
                const real = table.get(column.databaseName);
                if (!real) continue; // signalé par le test précédent
                const declaredType = String(column.type).toLowerCase();
                if (declaredType !== real.type) {
                    mismatches.push(`${column.databaseName} : type « ${declaredType} », schéma « ${real.type} »`);
                }
                if (column.isNullable !== real.nullable) {
                    mismatches.push(`${column.databaseName} : nullable=${column.isNullable}, schéma nullable=${real.nullable}`);
                }
                const declaredLength = column.length ? String(column.length) : null;
                if (declaredLength !== real.length) {
                    mismatches.push(`${column.databaseName} : longueur ${declaredLength}, schéma ${real.length}`);
                }
            }
            expect(mismatches).toEqual([]);
        });
    });

    it("lit les horodatages en texte, jamais en Date", () => {
        // Le contrôle qui protège la chaîne d'audit : une entité qui déclarerait
        // `Date` perdrait la microseconde sans rien signaler.
        const metadata = dataSource.getMetadata(AuditLog);
        const timestamp = metadata.columns.find((column) => column.databaseName === 'timestamp');
        expect(timestamp?.type).toBe('timestamp without time zone');
        expect(timestamp?.transformer).toBeUndefined();
    });
});
