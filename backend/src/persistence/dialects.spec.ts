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

    it('déclare une capacité pour chaque dialecte', () => {
        // Un dialecte ajouté sans sa fiche de capacités se comporterait comme
        // PostgreSQL par accident.
        for (const dialect of SUPPORTED_DIALECTS) {
            expect(CAPABILITIES[dialect]).toBeDefined();
        }
    });
});

describe('avertissements par dialecte', () => {
    it("PostgreSQL n'en produit aucun : c'est le moteur de référence", () => {
        expect(warningsFor('postgres')).toEqual([]);
    });

    it('SQLite avertit sur la réclamation et sur l’écrivain unique', () => {
        const capabilities = warningsFor('sqlite').map((warning) => warning.capability);
        expect(capabilities).toContain('canClaimTransactionally');
        expect(capabilities).toContain('supportsConcurrentWriters');
        // Mais pas sur les horodatages : SQLite les conserve.
        expect(capabilities).not.toContain('preservesMicroseconds');
    });

    it('MySQL avertit sur la troncature des horodatages, et le message dit pourquoi', () => {
        // C'est la divergence qui avait fait retirer MySQL de la pile Python : elle ne
        // lève aucune erreur, elle fait que le journal d'audit s'accuse lui-même.
        const [warning] = warningsFor('mysql').filter((item) => item.capability === 'preservesMicroseconds');
        expect(warning).toBeDefined();
        expect(warning.message).toContain('falsifié');
        expect(warning.message).toContain('DATETIME(6)');
    });

    it('MariaDB se comporte comme MySQL', () => {
        expect(warningsFor('mariadb').map((w) => w.capability)).toEqual(warningsFor('mysql').map((w) => w.capability));
    });

    it.each(SUPPORTED_DIALECTS)('%s : chaque avertissement nomme le dialecte et une conséquence', (dialect: Dialect) => {
        for (const warning of warningsFor(dialect)) {
            expect(warning.message).toContain(dialect);
            // Un avertissement qui ne dit pas ce qui casse est un avertissement qu'on
            // désactive.
            expect(warning.message.length).toBeGreaterThan(80);
        }
    });
});
