import { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * L'index du journal d'audit.
 *
 * **Deux chemins le parcourent, et tous deux dans le même ordre.** L'écriture cherche la
 * dernière entrée — celle dont l'empreinte devient le maillon suivant — et l'écran affiche
 * les plus récentes. Sans index, les deux trient la table entière : l'écriture d'audit
 * accompagne chaque connexion, chaque triage, chaque changement de réglage, et un journal
 * d'audit est fait pour durer.
 *
 * Même histoire que l'index de la file de scans, à un détail près : là-bas, MySQL avait
 * rendu le défaut visible en s'étranglant sous les verrous. Ici, rien ne l'aurait signalé —
 * le journal aurait simplement ralenti, mois après mois, sans qu'aucun test ne s'en
 * aperçoive puisqu'ils tournent tous sur une table quasi vide.
 *
 * `(timestamp, id)` et non `(timestamp DESC, id DESC)` : les deux moteurs parcourent un
 * index à l'envers, et une seule forme sert les deux sens.
 */
export class IndexJournalAudit1786800000001 implements MigrationInterface {
    name = 'IndexJournalAudit1786800000001';

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`CREATE INDEX \`idx_audit_log_ordre\` ON \`t_audit_log\` (\`timestamp\`, \`id\`)`);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`DROP INDEX \`idx_audit_log_ordre\` ON \`t_audit_log\``);
    }
}
