import { Client } from 'pg';
import { computeEntryHash } from '../domain/audit/audit-hash';
import { canonicalTimestamp, parseTimestamp } from '../domain/common/timestamp';
import { configurePostgresTypeParsers } from './pg-types';

/**
 * Contre un vrai serveur PostgreSQL, parce que c'est la seule façon de le savoir.
 *
 * Le pendant du `-m backends` de la suite Python, et pour la même raison : les défauts
 * que ces tests cherchent — une microseconde perdue par un pilote, un fuseau appliqué en
 * silence — sont invisibles à la lecture du code comme à un test qui simule la base.
 *
 * Hors de la suite par défaut : `testRegex` ne prend que `*.spec.ts`. Pour l'exécuter :
 *
 *     docker run -d --name zs-pg -e POSTGRES_PASSWORD=zanshin -p 55433:5432 postgres:16-alpine
 *     ZANSHIN_TEST_DATABASE_URL=postgres://postgres:zanshin@localhost:55433/postgres \
 *       npm run test:integration --workspace @zanshin/backend
 *
 * Sans la variable, la suite se saute d'elle-même en le disant — un test silencieusement
 * absent serait pire que pas de test du tout.
 */
const connectionString = process.env.ZANSHIN_TEST_DATABASE_URL;
const describeWithPostgres = connectionString ? describe : describe.skip;

/** Ce que PostgreSQL doit rendre pour chaque valeur écrite, et sa forme canonique. */
const CASES = [
    { written: '2026-08-10T08:13:58.322451', rendered: '2026-08-10 08:13:58.322451', canonical: '2026-08-10T08:13:58.322Z', microsecond: 322451 },
    { written: '2026-08-10T08:13:58', rendered: '2026-08-10 08:13:58', canonical: '2026-08-10T08:13:58.000Z', microsecond: 0 },
    // PostgreSQL retire les zéros de queue : 123 000 microsecondes reviennent en « .123 ».
    // Les lire comme l'entier 123 les décalerait d'un facteur mille.
    { written: '2026-01-02T03:04:05.123000', rendered: '2026-01-02 03:04:05.123', canonical: '2026-01-02T03:04:05.123Z', microsecond: 123000 },
    { written: '2026-03-01T12:00:00.000010', rendered: '2026-03-01 12:00:00.00001', canonical: '2026-03-01T12:00:00.000Z', microsecond: 10 },
    { written: '1999-12-31T23:59:59.999999', rendered: '1999-12-31 23:59:59.999999', canonical: '1999-12-31T23:59:59.999Z', microsecond: 999999 }
];

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
        for (const testCase of CASES) {
            await client.query('INSERT INTO zs_timestamp_probe (ts) VALUES ($1::timestamp)', [testCase.written]);
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

    it('rend exactement ce que le code attend', async () => {
        const { rows } = await client.query('SELECT ts FROM zs_timestamp_probe ORDER BY id');
        expect(rows.map((row) => row.ts)).toEqual(CASES.map((testCase) => testCase.rendered));
    });

    it('conserve la microseconde à la lecture', async () => {
        const { rows } = await client.query('SELECT ts FROM zs_timestamp_probe ORDER BY id');
        expect(rows.map((row) => parseTimestamp(row.ts).microsecond)).toEqual(CASES.map((testCase) => testCase.microsecond));
    });

    it('produit la forme canonique attendue', async () => {
        const { rows } = await client.query('SELECT ts FROM zs_timestamp_probe ORDER BY id');
        expect(rows.map((row) => canonicalTimestamp(row.ts))).toEqual(CASES.map((testCase) => testCase.canonical));
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
                expect(rows[0].ts).toBe(CASES[0].rendered);
            }
        } finally {
            if (previous === undefined) delete process.env.TZ;
            else process.env.TZ = previous;
        }
    });

    it("permet de recalculer l'empreinte d'audit d'une ligne relue de la base", async () => {
        // Le test qui compte : l'enchaînement complet — écriture, relecture, hachage —
        // et celui qui échouerait si un maillon perdait de l'information.
        const entry = {
            previousHash: null,
            timestamp: '2026-08-10T08:13:58.322451',
            operationType: 'LOGIN_SUCCESS',
            resourceId: 'alice',
            userId: 'alice',
            ipAddress: '10.0.0.4',
            userAgent: 'Mozilla/5.0',
            description: 'Connexion réussie'
        };
        const expected = computeEntryHash(entry);

        const { rows } = await client.query('SELECT $1::timestamp AS ts', [entry.timestamp]);

        expect(computeEntryHash({ ...entry, timestamp: rows[0].ts })).toBe(expected);
    });
});
