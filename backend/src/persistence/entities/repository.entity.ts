import { Column, Entity, PrimaryGeneratedColumn, JoinColumn, ManyToOne } from 'typeorm';
import { intColumn, stringColumn, timestampColumn, uuidColumn } from '../columns';
import { SshKey } from './ssh-key.entity';

/**
 * Un dépôt git surveillé.
 *
 * La classe Python s'appelle `ZanshinRepository` et non `Repository` : le nom court
 * entrait en collision avec la classe de dépôt de données. Ici la table est
 * `repository` et rien ne collisionne, mais le nom reste distinct de ceux de
 * `repositories/` pour la même raison de lisibilité.
 */
@Entity('repository')
export class Repository {
    @PrimaryGeneratedColumn({ type: 'integer' })
    id!: number;

    @Column(stringColumn())
    url!: string;

    @Column(stringColumn())
    branch!: string;

    /** Sous-répertoire à analyser, quand le dépôt en contient plusieurs projets. */
    @Column({ ...stringColumn(255, { nullable: true }), name: 'sub_path' })
    subPath!: string | null;

    @Column(stringColumn(255, { nullable: true }))
    name!: string | null;

    @Column({ ...intColumn({ nullable: true }), name: 'scan_interval_minutes' })
    scanIntervalMinutes!: number | null;

    /** Une expression cron l'emporte sur l'intervalle : un intervalle dérive à chaque
     *  exécution, si bien qu'un scan réglé pour les heures creuses finit en plein jour. */
    @Column({ ...stringColumn(255, { nullable: true }), name: 'scan_cron' })
    scanCron!: string | null;

    /** Estampillé **avant** le déclenchement : après, un scan plus long que l'intervalle
     *  ferait redéclencher la même cible à chaque tick. */
    @Column({ ...timestampColumn({ nullable: true }), name: 'last_scheduled_scan_at' })
    lastScheduledScanAt!: Date | null;

    @Column({ ...uuidColumn({ nullable: true }), name: 'ssh_key_id' })
    sshKeyId!: string | null;

    /** Déclarée pour la contrainte, pas pour être parcourue : `sshKeyId` reste la valeur
     *  que le code lit. `ON DELETE SET NULL` — la règle vivait dans le schéma Alembic et
     *  n'était écrite nulle part dans le modèle. */
    @ManyToOne(() => SshKey, { onDelete: 'SET NULL', createForeignKeyConstraints: true })
    @JoinColumn({ name: 'ssh_key_id' })
    sshKeyIdRelation?: SshKey | null;
}
