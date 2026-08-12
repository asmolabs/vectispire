import { BadRequestException, NotFoundException } from '@nestjs/common';
import { now } from '../domain/common/timestamp';
import { DataSource, EntityManager } from 'typeorm';
import { ENTITIES, Issue, Repository as GitRepository, Scan, STATE_OPEN, STATE_RESOLVED } from '../persistence/entities';
import { RepositoriesController } from './repositories.controller';
import type { AuthenticatedRequest } from './auth.guard';
import { connectToTestDatabase } from '../../test/database';


const asRequest = { user: { username: 'admin', role: 'admin' }, ip: '127.0.0.1' } as unknown as AuthenticatedRequest;

describe('API des dépôts', () => {
    let dataSource: DataSource;
    let manager: EntityManager;
    let release: () => Promise<void>;
    let controller: RepositoriesController;

    beforeAll(async () => {
        dataSource = await connectToTestDatabase();
    }, 30_000);

    beforeEach(async () => {
        const runner = dataSource.createQueryRunner();
        await runner.connect();
        await runner.startTransaction();
        manager = runner.manager;
        controller = new RepositoriesController(manager);
        release = async () => {
            await runner.rollbackTransaction();
            await runner.release();
        };
    });

    afterEach(async () => release());

    async function seedRepository(url: string): Promise<GitRepository> {
        return manager.save(GitRepository, Object.assign(new GitRepository(), { url, branch: 'main' }));
    }

    it('refuse une URL que git exécuterait', async () => {
        // Le contrôle vit dans le domaine, mais il doit être *câblé* : une régression ici
        // ne se voit pas au test unitaire du validateur.
        await expect(controller.create({ url: 'ext::sh -c whoami' }, asRequest)).rejects.toBeInstanceOf(BadRequestException);
    });

    it('crée un dépôt et le retrouve dans la liste', async () => {
        const created = await controller.create({ url: 'https://github.com/org/api.git', branch: 'develop' }, asRequest);
        const listed = await controller.list();
        expect(listed.map((row) => row.id)).toContain(created.id);
        expect(listed.find((row) => row.id === created.id)?.branch).toBe('develop');
    });

    it("distingue « jamais scanné » d'un scan existant", async () => {
        const never = await seedRepository('https://github.com/org/jamais.git');
        const scanned = await seedRepository('https://github.com/org/scanne.git');
        await manager.save(Scan, Object.assign(new Scan(), { repoId: scanned.id, branch: 'main', status: 'completed', findingsCount: 0, createdAt: now() }));

        const listed = await controller.list();
        expect(listed.find((row) => row.id === never.id)?.lastScan).toBeNull();
        expect(listed.find((row) => row.id === scanned.id)?.lastScan?.status).toBe('completed');
    });

    it('ne compte que les problèmes à traiter', async () => {
        const repository = await seedRepository('https://github.com/org/compte.git');
        for (const state of [STATE_OPEN, STATE_OPEN, STATE_RESOLVED]) {
            await manager.save(
                Issue,
                Object.assign(new Issue(), {
                    repoId: repository.id,
                    fingerprint: `f-${state}-${Math.round(performance.now() * 1000)}`,
                    type: 'sast',
                    identifier: 'regle',
                    severity: 'high',
                    state,
                    firstSeenAt: now(),
                    lastSeenAt: now(),
                    timesSeen: 1,
                    triageStatus: 'untriaged',
                    isKev: false
                })
            );
        }
        const listed = await controller.list();
        expect(listed.find((row) => row.id === repository.id)?.openIssues).toBe(2);
    });

    it('supprime le dépôt et son historique', async () => {
        const repository = await seedRepository('https://github.com/org/adieu.git');
        await manager.save(Scan, Object.assign(new Scan(), { repoId: repository.id, branch: 'main', status: 'completed', findingsCount: 0, createdAt: now() }));

        await controller.remove(repository.id, asRequest);

        expect(await manager.countBy(GitRepository, { id: repository.id })).toBe(0);
        // La cascade est déclarée en base (migration 0014) : si elle disparaissait, le
        // backlog d'une cible inexistante continuerait de compter dans les totaux.
        expect(await manager.countBy(Scan, { repoId: repository.id })).toBe(0);
    });

    it('rend 404 sur un dépôt inconnu plutôt que de réussir en silence', async () => {
        await expect(controller.remove(9_999_999, asRequest)).rejects.toBeInstanceOf(NotFoundException);
    });
});
