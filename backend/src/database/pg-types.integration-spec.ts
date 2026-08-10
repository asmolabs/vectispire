import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { Client } from 'pg';
import { computeEntryHash } from '../audit/audit-hash';
import { toPythonIsoformat } from '../common/python-timestamp';
import { configurePostgresTypeParsers } from './pg-types';

/**
 * Contre un vrai serveur PostgreSQL, parce que c'est la seule façon de le savoir.
 *
 * Le pendant du `-m backends` de la suite Python, et pour la même raison : les défauts
 * que ces tests cherchent — une microseconde perdue par un pilote, un fuseau appliqué
 * en silence — sont invisibles à la lecture du code et invisibles à un test qui
 * simule la base.
 *
 * Hors de la suite par défaut : `testRegex` ne prend que `*.spec.ts`. Pour l'exécuter :
 *
 *     docker run -d --name zs-pg -e POSTGRES_PASSWORD=zanshin -p 55432:5432 postgres:16-alpine
 *     ZANSHIN_TEST_DATABASE_URL=postgres://postgres:zanshin@localhost:55432/postgres \
 *       npx jest --testRegex '.*\.integration-spec\.ts$'
 *
 * Sans la variable, la suite se saute d'elle-même en le disant — un test silencieusement
 * absent serait pire que pas de test du tout.
 */
const connectionString = process.env.ZANSHIN_TEST_DATABASE_URL;
const describeWithPostgres = connectionString ? describe : describe.skip;

interface TimestampVector {
    isoformat: string;
    postgres: string;
    microsecond: number;
}

const vectors: TimestampVector[] = JSON.parse(readFileSync(join(__dirname, '../../test/vectors/python-timestamp.json'), 'utf8'));

if (!connectionString) {
    // eslint-disable-next-line no-console
    console.warn('ZANSHIN_TEST_DATABASE_URL absent : les tests PostgreSQL sont sautés.');
}

describeWithPostgres('décodage des horodatages par node-postgres', () => {
    let client: Client;

    beforeAll(async () => {
        configurePostgresTypeParsers();
        client = new Client({ connectionString });
        await client.connect();
        await client.query('CREATE TABLE IF NOT EXISTS zs_timestamp_probe (id serial primary key, ts timestamp)');
        await client.query('TRUNCATE zs_timestamp_probe');
        for (const vector of vectors) {
            await client.query('INSERT INTO zs_timestamp_probe (ts) VALUES ($1::timestamp)', [vector.isoformat]);
        }
    }, 30_000);

    afterAll(async () => {
        if (client) {
            await client.query('DROP TABLE IF EXISTS zs_timestamp_probe');
            await client.end();
        }
    });

    it('rend du texte, et non un Date', async () => {
        // Le cœur du correctif : `Date` ne sait pas porter une microseconde, donc
        // recevoir un `Date` signifie que l'information est déjà perdue.
        const { rows } = await client.query('SELECT ts FROM zs_timestamp_probe ORDER BY id LIMIT 1');
        expect(typeof rows[0].ts).toBe('string');
    });

    it('rend exactement ce que les vecteurs annoncent comme rendu PostgreSQL', async () => {
        const { rows } = await client.query('SELECT ts FROM zs_timestamp_probe ORDER BY id');
        expect(rows.map((row) => row.ts)).toEqual(vectors.map((vector) => vector.postgres));
    });

    it("reconstruit l'isoformat de Python pour chaque valeur", async () => {
        const { rows } = await client.query('SELECT ts FROM zs_timestamp_probe ORDER BY id');
        expect(rows.map((row) => toPythonIsoformat(row.ts))).toEqual(vectors.map((vector) => vector.isoformat));
    });

    it("ne dépend pas du fuseau de la machine", async () => {
        // Sans le correctif, la même ligne relue sous un autre TZ rend un autre instant.
        // Avec, le texte est le même partout — ce qui est la propriété qu'on veut, la
        // colonne étant un `timestamp without time zone` contenant de l'UTC.
        const previous = process.env.TZ;
        try {
            for (const timezone of ['UTC', 'America/Sao_Paulo', 'Asia/Kolkata']) {
                process.env.TZ = timezone;
                const { rows } = await client.query('SELECT ts FROM zs_timestamp_probe ORDER BY id LIMIT 1');
                expect(rows[0].ts).toBe(vectors[0].postgres);
            }
        } finally {
            if (previous === undefined) delete process.env.TZ;
            else process.env.TZ = previous;
        }
    });

    it("permet de recalculer l'empreinte d'audit d'une ligne relue de la base", async () => {
        // Le test qui compte : c'est l'enchaînement complet — écriture, relecture,
        // hachage — et c'est lui qui échouerait si un maillon perdait la microseconde.
        const auditVectors: { entry: Record<string, string | null>; expected: string }[] = JSON.parse(readFileSync(join(__dirname, '../../test/vectors/audit-hash.json'), 'utf8'));

        for (const vector of auditVectors) {
            const { rows } = await client.query('SELECT $1::timestamp AS ts', [vector.entry.timestamp]);
            const rehydrated = { ...vector.entry, timestamp: rows[0].ts } as Parameters<typeof computeEntryHash>[0];
            expect(computeEntryHash(rehydrated)).toBe(vector.expected);
        }
    });
});
