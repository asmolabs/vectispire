import { DataSource, EntityManager } from 'typeorm';
import { connectToTestDatabase } from '../../test/database';
import { now } from '../domain/common/timestamp';
import { Agent, AuditLog, KIND_REMOTE, Repository as GitRepository, Scan, STATUS_QUEUED } from '../persistence/entities';
import { AgentsAdminController } from './agents-admin.controller';
import { AuditLogService } from '../services/audit-log.service';
import type { AuthenticatedRequest } from './auth.guard';

/**
 * L'administration du ciblage : déclarer des étiquettes, et voir ce qui n'est pas routable.
 *
 * **Ce qui se vérifie ici est l'accord entre deux normalisations.** L'étiquette d'un agent
 * et l'exigence d'une cible sont saisies sur deux écrans différents, souvent à des mois
 * d'écart ; si elles ne se normalisent pas de la même façon, le scan attend un agent qui
 * est là et rien ne l'explique. Le second test est précisément cette panne, rendue visible.
 */
describe('administration du ciblage', () => {
    let dataSource: DataSource;
    let manager: EntityManager;
    let release: () => Promise<void>;
    let controller: AgentsAdminController;
    const original = { ...process.env };

    beforeAll(async () => {
        dataSource = await connectToTestDatabase();
    }, 30_000);

    beforeEach(async () => {
        const runner = dataSource.createQueryRunner();
        await runner.connect();
        await runner.startTransaction();
        manager = runner.manager;
        controller = new AgentsAdminController(manager, new AuditLogService());
        release = async () => {
            await runner.rollbackTransaction();
            await runner.release();
        };
    });

    afterEach(async () => {
        await release();
        process.env = { ...original };
    });

    const asAdmin = () => ({ user: { username: 'admin' }, ip: null }) as unknown as AuthenticatedRequest;

    async function seedAgent(labels: string | null, enabled = true): Promise<Agent> {
        return manager.save(
            Agent,
            Object.assign(new Agent(), {
                name: `agent-${Math.random().toString(36).slice(2, 8)}`,
                kind: KIND_REMOTE,
                credentialsMode: 'local',
                labels,
                enabled,
                maxConcurrent: 1,
                createdAt: now()
            })
        );
    }

    async function queueScan(requiredAgentLabel: string | null): Promise<Scan> {
        const repository = await manager.save(
            GitRepository,
            Object.assign(new GitRepository(), { url: `https://exemple/${Math.random().toString(36).slice(2)}.git`, branch: 'main', requiredAgentLabel })
        );
        return manager.save(
            Scan,
            Object.assign(new Scan(), { repoId: repository.id, branch: 'main', status: STATUS_QUEUED, requiredAgentLabel, createdAt: now() })
        );
    }

    describe('étiquettes déclarées', () => {
        it('normalise ce que l’opérateur saisit', async () => {
            const agent = await seedAgent(null);

            await controller.update(agent.id, { labels: ' Production , RÉSEAU-Client ' }, asAdmin());

            expect((await manager.findOneByOrFail(Agent, { id: agent.id })).labels).toBe('production,réseau-client');
        });

        it('traite un champ vidé comme « plus aucune étiquette »', async () => {
            // Stocker la chaîne vide donnerait une étiquette que rien n'exige jamais, ce qui
            // est inoffensif — mais la liste des non-routables la compterait comme servie.
            const agent = await seedAgent('prod');

            await controller.update(agent.id, { labels: '   ' }, asAdmin());

            expect((await manager.findOneByOrFail(Agent, { id: agent.id })).labels).toBeNull();
        });

        it('laisse les étiquettes intactes quand la requête n’en parle pas', async () => {
            // La route sert aussi à activer/désactiver : un `PATCH { enabled: false }` ne
            // doit pas effacer au passage ce qui décide de ce que cet agent peut prendre.
            const agent = await seedAgent('prod');

            await controller.update(agent.id, { enabled: false }, asAdmin());

            expect((await manager.findOneByOrFail(Agent, { id: agent.id })).labels).toBe('prod');
        });

        it('trace le changement, qui est une décision d’autorisation', async () => {
            // Élargir les étiquettes d'un agent lui ouvre des cibles auxquelles il n'avait
            // pas accès — au même titre qu'un changement de rôle, et par un geste aussi
            // discret. Sans trace, personne ne saurait qui l'a fait.
            const agent = await seedAgent(null);

            await controller.update(agent.id, { labels: 'client' }, asAdmin());

            // Par l'entité et non par du SQL : `$1` et `?` ne s'écrivent pas pareil selon le
            // moteur, et ce test doit passer sur les deux.
            const entries = await manager.find(AuditLog, { where: { resourceId: agent.id } });
            expect(entries.some((entry) => (entry.description ?? '').includes('client'))).toBe(true);
        });
    });

    describe('scans que personne ne peut prendre', () => {
        it('nomme l’étiquette et compte les scans en attente', async () => {
            // **Sans cet écran, l'attente est muette.** La page Dépôts dit « en attente »,
            // ce qui est vrai et n'explique rien, et le scan reste là indéfiniment.
            await seedAgent('prod');
            await queueScan('client');
            await queueScan('client');

            expect(await controller.unroutable()).toEqual([{ label: 'client', queued: 2 }]);
        });

        it('ne signale rien quand un agent activé porte l’étiquette', async () => {
            await seedAgent('client,prod');
            await queueScan('client');

            expect(await controller.unroutable()).toEqual([]);
        });

        it('compte un agent désactivé comme absent', async () => {
            // Un agent désactivé ne réclame plus : ses étiquettes ne servent personne, et
            // les compter ferait passer pour routable une file qui ne bouge pas.
            await seedAgent('client', false);
            await queueScan('client');

            expect(await controller.unroutable()).toEqual([{ label: 'client', queued: 1 }]);
        });

        it('tient compte du travailleur intégré, qui n’est pas une ligne de la table', async () => {
            // Ses étiquettes viennent de son environnement. Les oublier annoncerait bloqué
            // ce qui tourne — un avertissement faux, qu'on apprend vite à ignorer.
            process.env.ZANSHIN_WORKER_LABELS = 'client';
            await queueScan('client');

            expect(await controller.unroutable()).toEqual([]);
        });

        it('ignore les scans sans exigence', async () => {
            await queueScan(null);

            expect(await controller.unroutable()).toEqual([]);
        });
    });
});
