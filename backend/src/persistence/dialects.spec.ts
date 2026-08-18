import { CAPABILITIES, Dialect, SUPPORTED_DIALECTS, parseDialect, warningsFor } from './dialects';

describe('dialectes pris en charge', () => {
    it('accepte les orthographes courantes', () => {
        expect(parseDialect('postgresql')).toBe('postgres');
        expect(parseDialect('PostgreSQL')).toBe('postgres');
        expect(parseDialect(' pg ')).toBe('postgres');
        expect(parseDialect('sqlite3')).toBe('sqlite');
        expect(parseDialect('MySQL')).toBe('mysql');
    });

    it('refuse un dialecte inconnu en nommant ceux qui existent', () => {
        expect(() => parseDialect('oracle')).toThrow(/oracle/);
        expect(() => parseDialect('oracle')).toThrow(/postgres/);
    });

    it('declares a capability sheet for every dialect', () => {
        // A dialect added without its capability sheet would behave like
        // PostgreSQL par accident.
        for (const dialect of SUPPORTED_DIALECTS) {
            expect(CAPABILITIES[dialect]).toBeDefined();
        }
    });
});

describe('per-dialect warnings', () => {
    it("PostgreSQL produces none: it is the reference engine", () => {
        expect(warningsFor('postgres')).toEqual([]);
    });

    it('SQLite warns about claiming and about the single writer', () => {
        const capabilities = warningsFor('sqlite').map((warning) => warning.capability);
        expect(capabilities).toContain('canClaimTransactionally');
        expect(capabilities).toContain('supportsConcurrentWriters');
        // Mais pas sur les horodatages : SQLite les conserve.
        expect(capabilities).not.toContain('preservesMicroseconds');
    });

    it("MySQL no longer warns about timestamps: the cause is gone", () => {
        // C'est la divergence qui avait fait retirer MySQL de la pile Python — elle ne
        // raised no error, it made the audit log accuse itself. `datetime(6)` is now
        // declared in `column-types.ts` and the connection is pinned to UTC on both sides,
        // so the warning would have no object. A warning describing a fixed defect teaches
        // people to ignore warnings.
        expect(warningsFor('mysql').map((item) => item.capability)).not.toContain('preservesMicroseconds');
    });

    it('MySQL does warn about short claim batches', () => {
        // The real divergence, measured: skipped rows count against the `LIMIT`. No row is
        // served twice — this is throughput, not correctness — and the message has to say
        // so, otherwise it reads as a safety defect.
        const [warning] = warningsFor('mysql').filter((item) => item.capability === 'claimsCompleteBatches');
        expect(warning).toBeDefined();
        expect(warning.message).toContain('served twice');
        expect(warning.message).toContain('throughput');
    });

    it('MariaDB warns less than MySQL, once measured', () => {
        // **This test used to assert the opposite**, and its old name said why: "for want
        // of having been measured". Three of MariaDB's four capabilities were inherited from
        // MySQL out of caution, and wrong. The caution was not neutral:
        // `canClaimTransactionally` set to `false` sent claiming down the lock-free path,
        // where the second claimant waited on the first's transaction until it expired.
        //
        // Measured on two concurrent claimants and four queued scans, MariaDB returns a
        // lot complet — comme PostgreSQL, et mieux que MySQL. Il ne lui reste que l'absence
        // de `NULLS LAST`, qu'il partage avec sa famille.
        const mariadb = warningsFor('mariadb').map((item) => item.capability);
        expect(mariadb).toEqual(['supportsNullsLast']);
        expect(mariadb.length).toBeLessThan(warningsFor('mysql').length);
    });

    it('SQLite avertit sur ce qu’il ne peut structurellement pas faire', () => {
        // One writer, and claiming that cannot be transactional: both are properties of the
        // engine, not defects to fix. What matters is that they are said at startup rather
        // than discovered through a corrupted database.
        const sqlite = warningsFor('sqlite').map((item) => item.capability);
        expect(sqlite).toContain('canClaimTransactionally');
        expect(sqlite).toContain('supportsConcurrentWriters');
    });

    it.each(SUPPORTED_DIALECTS)('%s: every warning names the dialect and a consequence', (dialect: Dialect) => {
        for (const warning of warningsFor(dialect)) {
            expect(warning.message).toContain(dialect);
            // Un avertissement qui ne dit pas ce qui casse est un avertissement qu'on
            // switches off.
            expect(warning.message.length).toBeGreaterThan(80);
        }
    });
});
