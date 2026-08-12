import { Column, Entity, PrimaryColumn, PrimaryGeneratedColumn } from 'typeorm';
import { intColumn, jsonColumn, stringColumn, textColumn, timestampColumn } from '../columns';

export const OUTBOX_PENDING = 'pending';
export const OUTBOX_SENT = 'sent';
export const OUTBOX_FAILED = 'failed';

/**
 * Une notification en attente d'envoi.
 *
 * Le motif outbox, et sa raison d'être tient en une phrase : le message doit devenir
 * durable **au même instant** que l'état qu'il décrit, sinon la panne qu'il est censé
 * prévenir se contente de descendre d'une ligne. Il est donc écrit dans la transaction
 * qui crée les problèmes, et relayé plus tard par l'ordonnanceur.
 *
 * La livraison est au-moins-une-fois — le POST peut réussir et la transaction qui le
 * marque envoyé échouer — d'où un identifiant de message dans la charge utile : le
 * récepteur est le seul endroit où cette ambiguïté peut être levée.
 */
@Entity('t_outbox_message')
export class OutboxMessage {
    @PrimaryGeneratedColumn('uuid')
    id!: string;

    @Column({ ...stringColumn(50), name: 'message_type' })
    messageType!: string;

    @Column(jsonColumn())
    payload!: unknown;

    @Column(stringColumn(20))
    status!: string;

    @Column(intColumn())
    attempts!: number;

    /** Recul exponentiel, de 60 s à une heure, sur huit tentatives. */
    @Column({ ...timestampColumn({ nullable: true }), name: 'next_attempt_at' })
    nextAttemptAt!: Date | null;

    @Column({ ...textColumn({ nullable: true }), name: 'last_error' })
    lastError!: string | null;

    @Column({ ...timestampColumn(), name: 'created_at' })
    createdAt!: Date;

    @Column({ ...timestampColumn({ nullable: true }), name: 'sent_at' })
    sentAt!: Date | null;
}
