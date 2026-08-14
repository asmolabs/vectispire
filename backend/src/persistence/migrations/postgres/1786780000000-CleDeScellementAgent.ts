import { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * La clé publique éphémère qu'un agent annonce pour recevoir des secrets scellés.
 *
 * **Ce que TLS ne donne pas.** La clé de déploiement d'un dépôt voyage du plan de contrôle
 * vers l'agent. TLS la protège de bout en bout *à condition que personne ne termine TLS en
 * chemin* — or la plupart des déploiements ont un proxy inverse. À cet endroit, la clé SSH
 * est en clair : dans un vidage mémoire, dans un journal de débogage, et pour qui
 * administre le proxy.
 *
 * Nullable, et elle le reste : un agent d'une version antérieure n'en annonce aucune et
 * continue de recevoir la clé en clair sur une liaison chiffrée, comme avant. C'est ce qui
 * fait de ce changement une amélioration déployable plutôt qu'une rupture de contrat.
 *
 * Elle ne vaut rien seule — c'est une clé *publique*, et sa moitié privée ne quitte jamais
 * le processus de l'agent. Rien à protéger ici, donc, sinon son authenticité : elle arrive
 * par une route authentifiée par la clé d'API de l'agent.
 */
export class CleDeScellementAgent1786780000000 implements MigrationInterface {
    name = 'CleDeScellementAgent1786780000000';

    public async up(queryRunner: QueryRunner): Promise<void> {
        // 255 : une clé X25519 au format SPKI/DER tient en 44 caractères base64. La marge
        // évite d'avoir à migrer si le format d'encodage change un jour.
        await queryRunner.query(`ALTER TABLE "t_agent" ADD COLUMN "sealing_public_key" VARCHAR(255)`);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE "t_agent" DROP COLUMN "sealing_public_key"`);
    }
}
