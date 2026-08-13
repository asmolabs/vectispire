import { DataSource, EntityManager } from 'typeorm';
import { MAX_ATTEMPTS } from '../domain/notifications/backoff';
import { OUTBOX_FAILED, OUTBOX_PENDING, OUTBOX_SENT, OutboxMessage } from '../persistence/entities';
import { NotificationService } from './notification.service';
import { OutboxService } from './outbox.service';
import type { SettingsService } from './settings.service';
import { connectToTestDatabase } from '../../test/database';

/**
 * Le relais d'outbox, contre une vraie base.
 *
 * Ce qui se vérifie ici ne se voit pas dans un test à doubles : qu'un message échoué
 * revienne bien dû après son délai, qu'un message abandonné **reste** (avec sa dernière
 * erreur) au lieu d'être supprimé, et qu'un message pas encore dû ne soit pas repris à
 * chaque passage — le défaut qui transformerait un webhook mal configuré en charge
 * permanente.
 */

function settings(values: Record<string, string>): SettingsService {
    return {
        get: async (key: string, fallback = '') => values[key] ?? fallback,
        isEnabled: async (key: string, fallback: boolean) => (values[key] ?? (fallback ? 'true' : 'false')) === 'true'
    } as unknown as SettingsService;
}

/** Un service de notification dont la livraison est pilotée par le test. */
function notifier(deliver: () => Promise<void>): NotificationService {
    const service = new NotificationService(settings({ notification_webhook_url: 'https://exemple.test/hook' }));
    service.deliver = deliver as NotificationService['deliver'];
    return service;
}

describe("relais de l'outbox", () => {
    let dataSource: DataSource;
    let manager: EntityManager;
    let release: () => Promise<void>;

    beforeAll(async () => {
        dataSource = await connectToTestDatabase();
    }, 30_000);

    beforeEach(async () => {
        const runner = dataSource.createQueryRunner();
        await runner.connect();
        await runner.startTransaction();
        manager = runner.manager;
        release = async () => {
            await runner.rollbackTransaction();
            await runner.release();
        };
    });

    afterEach(async () => release());

    function outbox(deliver: () => Promise<void>): OutboxService {
        return new OutboxService(manager, notifier(deliver));
    }

    const ok = async () => {};
    const refused = async () => {
        throw new Error('HTTP 503');
    };

    it('estampille un identifiant de message dans la charge', async () => {
        // La livraison est au-moins-une-fois : le POST peut réussir et la transaction qui
        // le marque envoyé échouer. Le récepteur est le seul endroit où lever l'ambiguïté.
        const message = await outbox(ok).enqueue(manager, { text: 'bonjour' });

        expect((message.payload as { message_id: string }).message_id).toBe(message.id);
    });

    it('livre un message dû et le marque envoyé', async () => {
        const service = outbox(ok);
        await service.enqueue(manager, { text: 'bonjour' });

        expect(await service.relay()).toEqual({ sent: 1, failed: 0, abandoned: 0 });

        const [row] = await manager.find(OutboxMessage);
        expect(row.status).toBe(OUTBOX_SENT);
        expect(row.sentAt).not.toBeNull();
        expect(row.lastError).toBeNull();
    });

    it('replanifie un échec au lieu de le perdre', async () => {
        const service = outbox(refused);
        await service.enqueue(manager, { text: 'bonjour' });

        expect(await service.relay()).toEqual({ sent: 0, failed: 1, abandoned: 0 });

        const [row] = await manager.find(OutboxMessage);
        expect(row.status).toBe(OUTBOX_PENDING);
        expect(row.attempts).toBe(1);
        expect(row.lastError).toContain('HTTP 503');
        expect(row.nextAttemptAt).not.toBeNull();
    });

    it("ne reprend pas un message dont l'heure n'est pas venue", async () => {
        // Sans cela, un webhook mal configuré serait repris à chaque passage — une erreur
        // de saisie transformée en charge permanente.
        const service = outbox(refused);
        await service.enqueue(manager, { text: 'bonjour' });
        await service.relay();

        expect(await service.relay()).toEqual({ sent: 0, failed: 0, abandoned: 0 });
        expect((await manager.find(OutboxMessage))[0].attempts).toBe(1);
    });

    it('abandonne au plafond, sans supprimer', async () => {
        // Un message que personne ne recevra jamais est exactement ce qu'un opérateur doit
        // pouvoir retrouver.
        const service = outbox(refused);
        const message = await service.enqueue(manager, { text: 'bonjour' });
        await manager.update(OutboxMessage, { id: message.id }, { attempts: MAX_ATTEMPTS - 1, nextAttemptAt: null });

        expect(await service.relay()).toEqual({ sent: 0, failed: 0, abandoned: 1 });

        const [row] = await manager.find(OutboxMessage);
        expect(row.status).toBe(OUTBOX_FAILED);
        expect(row.nextAttemptAt).toBeNull();
        expect(row.lastError).toContain('HTTP 503');
    });

    it('compte par état, abandons compris', async () => {
        const service = outbox(refused);
        const abandoned = await service.enqueue(manager, { text: 'perdu' });
        await manager.update(OutboxMessage, { id: abandoned.id }, { attempts: MAX_ATTEMPTS - 1, nextAttemptAt: null });
        await service.relay();
        await service.enqueue(manager, { text: 'en attente' });

        expect(await service.counts()).toEqual({ [OUTBOX_FAILED]: 1, [OUTBOX_PENDING]: 1 });
    });

    it('purge les messages livrés depuis assez longtemps, et eux seuls', async () => {
        const service = outbox(ok);
        const old = await service.enqueue(manager, { text: 'ancien' });
        await service.relay();
        await manager.update(OutboxMessage, { id: old.id }, { sentAt: new Date(Date.now() - 30 * 86_400_000) });
        await service.enqueue(manager, { text: 'en attente' });

        expect(await service.pruneSent()).toBe(1);
        expect(await manager.count(OutboxMessage)).toBe(1);
    });

    it('ne perd pas les autres messages quand un seul refuse', async () => {
        // Un webhook injoignable ne doit pas arrêter le reste du passage.
        let calls = 0;
        const service = outbox(async () => {
            calls += 1;
            if (calls === 1) throw new Error('HTTP 500');
        });
        await service.enqueue(manager, { text: 'premier' });
        await service.enqueue(manager, { text: 'second' });

        expect(await service.relay()).toEqual({ sent: 1, failed: 1, abandoned: 0 });
    });
});
