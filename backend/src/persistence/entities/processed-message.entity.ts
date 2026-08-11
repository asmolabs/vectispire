import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';
import { stringColumn, timestampColumn, uuidColumn } from '../columns';

/**
 * L'inbox d'idempotence : ce qu'un agent a déjà rendu.
 *
 * Un agent réémet son rapport tant que le transport échoue, en réutilisant le même
 * identifiant de message. Sans cette table, chaque réémission réappliquerait
 * l'ingestion — donc incrémenterait `timesSeen` sur chaque problème, et gonflerait
 * l'historique d'un dépôt pour une raison qui n'a rien à voir avec son code.
 *
 * Le marqueur est **posé sans être commité** : c'est l'ingestion qui commite, et ce
 * commit unique rend le marqueur et le résultat atomiques.
 */
@Entity('processed_message')
export class ProcessedMessage {
    @PrimaryGeneratedColumn({ type: 'integer' })
    id!: number;

    @Column({ ...stringColumn(64), name: 'message_id' })
    messageId!: string;

    @Column({ ...stringColumn(50), name: 'message_type' })
    messageType!: string;

    @Column({ ...uuidColumn({ nullable: true }), name: 'agent_id' })
    agentId!: string | null;

    @Column({ ...timestampColumn(), name: 'processed_at' })
    processedAt!: Date;
}
