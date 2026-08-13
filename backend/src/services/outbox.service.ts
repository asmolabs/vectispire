import { Injectable, Logger } from '@nestjs/common';
import { InjectEntityManager } from '@nestjs/typeorm';
import { EntityManager, IsNull, LessThanOrEqual, Or } from 'typeorm';
import { randomUUID } from 'node:crypto';
import { now } from '../domain/common/timestamp';
import { MAX_ATTEMPTS, MAX_PER_PASS, SENT_RETENTION_DAYS, nextAttempt, recordableError } from '../domain/notifications/backoff';
import { OUTBOX_FAILED, OUTBOX_PENDING, OUTBOX_SENT, OutboxMessage } from '../persistence/entities';
import { NotificationService } from './notification.service';

export const TYPE_SCAN_DELTA = 'scan_delta';

/**
 * Le relais qui vide la file de notifications.
 *
 * Séparé du service de notification à dessein : celui-ci possède *quand un message a droit
 * à une nouvelle chance*, l'autre *quoi dire et comment le dire*.
 *
 * **`enqueue` n'ouvre pas de transaction, et c'est tout le point** : le message doit
 * devenir durable au même instant que l'état qu'il décrit, sinon la panne qu'il est censé
 * prévenir se contente de descendre d'une ligne.
 */
@Injectable()
export class OutboxService {
    private readonly logger = new Logger(OutboxService.name);

    constructor(
        @InjectEntityManager() private readonly manager: EntityManager,
        private readonly notifications: NotificationService
    ) {}

    /**
     * Ajoute un message à la transaction **déjà ouverte par l'appelant**.
     *
     * Un identifiant de message est estampillé dans la charge parce que la livraison est
     * au-moins-une-fois — le POST peut réussir et la transaction qui le marque envoyé
     * échouer — et que le récepteur est le seul endroit où cette ambiguïté peut être levée.
     */
    async enqueue(manager: EntityManager, payload: Record<string, unknown>, messageType = TYPE_SCAN_DELTA): Promise<OutboxMessage> {
        const id = randomUUID();
        return manager.save(
            Object.assign(new OutboxMessage(), {
                id,
                messageType,
                payload: { ...payload, message_id: id },
                status: OUTBOX_PENDING,
                attempts: 0,
                nextAttemptAt: null,
                lastError: null,
                createdAt: now(),
                sentAt: null
            })
        );
    }

    /**
     * Tente une fois chaque message dû. Rend le nombre livré.
     *
     * **Ne lève jamais** : ceci tourne sur le tour d'entretien à côté des autres travaux,
     * et un webhook injoignable ne doit pas arrêter le reste.
     */
    async relay(limit = MAX_PER_PASS): Promise<{ sent: number; failed: number; abandoned: number }> {
        const at = now();
        const due = await this.manager.find(OutboxMessage, {
            where: { status: OUTBOX_PENDING, nextAttemptAt: Or(IsNull(), LessThanOrEqual(at)) },
            order: { createdAt: 'ASC' },
            take: limit
        });

        let sent = 0;
        let failed = 0;
        let abandoned = 0;

        for (const message of due) {
            const attempts = (message.attempts ?? 0) + 1;
            try {
                await this.notifications.deliver(message.payload as Record<string, unknown>);
            } catch (error) {
                const outcome = nextAttempt(attempts, at);
                await this.manager.update(OutboxMessage, { id: message.id }, {
                    attempts,
                    lastError: recordableError(error),
                    status: outcome.abandoned ? OUTBOX_FAILED : OUTBOX_PENDING,
                    nextAttemptAt: outcome.nextAttemptAt
                });

                if (outcome.abandoned) {
                    abandoned += 1;
                    this.logger.error(`Notification ${message.id} abandonnée après ${attempts} tentatives : ${recordableError(error)}`);
                } else {
                    failed += 1;
                    this.logger.warn(
                        `Notification ${message.id} échouée (tentative ${attempts}/${MAX_ATTEMPTS}), reprise vers ${outcome.nextAttemptAt?.toISOString()}.`
                    );
                }
                continue;
            }

            await this.manager.update(OutboxMessage, { id: message.id }, {
                attempts,
                status: OUTBOX_SENT,
                sentAt: at,
                nextAttemptAt: null,
                lastError: null
            });
            sent += 1;
        }

        if (sent > 0) this.logger.log(`Outbox : ${sent} message(s) livré(s).`);
        return { sent, failed, abandoned };
    }

    /** Supprime les messages livrés depuis assez longtemps. La table est écrite à chaque scan. */
    async pruneSent(days = SENT_RETENTION_DAYS): Promise<number> {
        const cutoff = new Date(now().getTime() - days * 86_400_000);
        const result = await this.manager
            .createQueryBuilder()
            .delete()
            .from(OutboxMessage)
            .where('status = :status AND sent_at IS NOT NULL AND sent_at < :cutoff', { status: OUTBOX_SENT, cutoff })
            .execute();
        return result.affected ?? 0;
    }

    /** Les compteurs par état — dont les abandons, que l'écran doit montrer. */
    async counts(): Promise<Record<string, number>> {
        const rows = await this.manager
            .createQueryBuilder(OutboxMessage, 'message')
            .select('message.status', 'status')
            .addSelect('COUNT(*)', 'count')
            .groupBy('message.status')
            .getRawMany<{ status: string; count: string }>();

        return Object.fromEntries(rows.map((row) => [row.status, Number(row.count)]));
    }
}
