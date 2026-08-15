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

    it('MariaDB avertit moins que MySQL, une fois mesuré', () => {
        // **Ce test affirmait l'inverse**, et son ancien nom le disait : « faute d'avoir été
        // mesuré ». Trois des quatre capacités de MariaDB étaient héritées de MySQL par
        // prudence, et fausses. La prudence n'était pas neutre : `canClaimTransactionally`
        // à `false` envoyait la réclamation sur le chemin sans verrou, où le deuxième
        // réclamant attendait la transaction du premier jusqu'à expiration.
        //
        // Mesuré sur deux réclamants concurrents et quatre scans en file, MariaDB rend un
        // lot complet — comme PostgreSQL, et mieux que MySQL. Il ne lui reste que l'absence
        // de `NULLS LAST`, qu'il partage avec sa famille.
        const mariadb = warningsFor('mariadb').map((item) => item.capability);
        expect(mariadb).toEqual(['supportsNullsLast']);
        expect(mariadb.length).toBeLessThan(warningsFor('mysql').length);
    });

    it('SQLite avertit sur ce qu’il ne peut structurellement pas faire', () => {
        // Un seul écrivain, et une réclamation qui ne peut pas être transactionnelle : les
        // deux sont des propriétés du moteur, pas des défauts à corriger. Ce qui compte est
        // qu'elles soient dites au démarrage plutôt que découvertes par une base corrompue.
        const sqlite = warningsFor('sqlite').map((item) => item.capability);
        expect(sqlite).toContain('canClaimTransactionally');
        expect(sqlite).toContain('supportsConcurrentWriters');
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
