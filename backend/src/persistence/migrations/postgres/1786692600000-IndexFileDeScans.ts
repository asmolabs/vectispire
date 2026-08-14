import { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * L'index de la file de scans.
 *
 * **Trouvé en faisant tourner la campagne sur MySQL**, pas en lisant le code. La
 * réclamation cherche `status = 'pending'` puis trie par date ; sans index, le moteur
 * parcourt la table entière et pose un verrou sur chaque ligne examinée. `SKIP LOCKED`
 * saute celles déjà prises, mais les transactions concurrentes finissent par s'attendre —
 * MySQL rendait « Lock wait timeout exceeded » sous le test à dix connexions.
 *
 * PostgreSQL tolérait l'absence d'index sur une table de test, ce qui a laissé le défaut
 * invisible. Il est posé ici aussi : la cause est la même, seule sa manifestation
 * diffère, et une file de production ne restera pas petite.
 */
export class IndexFileDeScans1786692600000 implements MigrationInterface {
    name = 'IndexFileDeScans1786692600000';

    public async up(queryRunner: QueryRunner): Promise<void> {
        // L'ordre des colonnes suit celui de la requête : filtre d'abord, tri ensuite.
        await queryRunner.query(`CREATE INDEX "idx_scan_file" ON "t_scan" ("status", "created_at", "id")`);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`DROP INDEX "idx_scan_file"`);
    }
}
