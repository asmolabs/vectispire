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

    it("MySQL n'avertit plus sur les horodatages : la cause est supprimée", () => {
        // C'est la divergence qui avait fait retirer MySQL de la pile Python — elle ne
        // levait aucune erreur, elle faisait que le journal d'audit s'accusait lui-même.
        // `datetime(6)` est désormais déclaré dans `column-types.ts` et la connexion est
        // fixée en UTC des deux côtés, donc l'avertissement n'aurait plus d'objet. Un
        // avertissement qui décrit un défaut corrigé apprend à ignorer les avertissements.
        expect(warningsFor('mysql').map((item) => item.capability)).not.toContain('preservesMicroseconds');
    });

    it('MySQL avertit en revanche sur les lots de réclamation courts', () => {
        // Le vrai écart, mesuré : les lignes sautées comptent dans le `LIMIT`. Aucune
        // ligne n'est remise deux fois — c'est du débit, pas de la correction — et le
        // message doit le dire, sinon il se lit comme un défaut de sûreté.
        const [warning] = warningsFor('mysql').filter((item) => item.capability === 'claimsCompleteBatches');
        expect(warning).toBeDefined();
        expect(warning.message).toContain('deux fois');
        expect(warning.message).toContain('débit');
    });

    it("MariaDB avertit plus que MySQL, faute d'avoir été mesuré", () => {
        // Hérité par prudence : le supposer identique à MySQL serait exactement le
        // raisonnement que la mesure a dû corriger.
        const mariadb = warningsFor('mariadb').map((item) => item.capability);
        expect(mariadb).toContain('preservesMicroseconds');
        expect(mariadb).toContain('canClaimTransactionally');
        expect(mariadb.length).toBeGreaterThan(warningsFor('mysql').length);
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
