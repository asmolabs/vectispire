import { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Le ciblage d'un scan vers un agent capable.
 *
 * **La file n'était routée par aucun critère.** N'importe quel agent enregistré réclamait
 * n'importe quel scan, et le premier qui demandait était servi. Un agent posé dans un
 * segment de moindre confiance — parce qu'il doit y atteindre un dépôt, ce qui est
 * précisément la raison d'exister des agents distants — pouvait donc réclamer les scans de
 * tous les autres dépôts, et recevoir leurs clés de déploiement avec.
 *
 * Trois colonnes, toutes nullables, toutes `null` par défaut : une installation existante
 * ne change pas de comportement. Sur le scan, la valeur est **recopiée** depuis la cible à
 * la mise en file, et non lue par jointure — la réclamation est un `FOR UPDATE SKIP LOCKED`
 * sur cette seule table, et y joindre une autre ferait verrouiller ses lignes aussi.
 */
export class CiblageDesAgents1786790000001 implements MigrationInterface {
    name = 'CiblageDesAgents1786790000001';

    public async up(queryRunner: QueryRunner): Promise<void> {
        for (const table of ['t_repository', 't_container', 't_scan']) {
            await queryRunner.query(`ALTER TABLE \`${table}\` ADD COLUMN \`required_agent_label\` VARCHAR(255) NULL`);
        }

        // La réclamation filtre désormais aussi sur cette colonne : l'index de la file la
        // reçoit, sans quoi un agent étiqueté parcourrait la file entière à chaque tour.
        await queryRunner.query(`DROP INDEX \`idx_scan_file\` ON \`t_scan\``);
        await queryRunner.query(`CREATE INDEX \`idx_scan_file\` ON \`t_scan\` (\`status\`, \`required_agent_label\`, \`created_at\`, \`id\`)`);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`DROP INDEX \`idx_scan_file\` ON \`t_scan\``);
        await queryRunner.query(`CREATE INDEX \`idx_scan_file\` ON \`t_scan\` (\`status\`, \`created_at\`, \`id\`)`);
        for (const table of ['t_repository', 't_container', 't_scan']) {
            await queryRunner.query(`ALTER TABLE \`${table}\` DROP COLUMN \`required_agent_label\``);
        }
    }
}
