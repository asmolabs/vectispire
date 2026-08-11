import { BadRequestException, NotFoundException } from '@nestjs/common';
import { now } from '../domain/common/timestamp';
import { DataSource, EntityManager } from 'typeorm';
import { Container, ENTITIES, Issue, Scan, STATE_OPEN, STATE_RESOLVED } from '../persistence/entities';
import { ContainersController } from './containers.controller';
import type { AuthenticatedRequest } from './auth.guard';

const connectionString = process.env.ZANSHIN_TEST_DATABASE_URL;
const describeWithPostgres = connectionString ? describe : describe.skip;

const asRequest = { user: { username: 'admin', role: 'ADMIN' }, ip: '127.0.0.1' } as unknown as AuthenticatedRequest;

describeWithPostgres('API des conteneurs', () => {
    let dataSource: DataSource;
    let manager: EntityManager;
    let release: () => Promise<void>;
    let controller: ContainersController;

    beforeAll(async () => {
        dataSource = new DataSource({ type: 'postgres', url: connectionString, entities: ENTITIES, synchronize: false });
        await dataSource.initialize();
    }, 30_000);

    afterAll(async () => {
        if (dataSource?.isInitialized) await dataSource.destroy();
    });

    beforeEach(async () => {
        const runner = dataSource.createQueryRunner();
        await runner.connect();
        await runner.startTransaction();
        manager = runner.manager;
        controller = new ContainersController(manager);
        release = async () => {
            await runner.rollbackTransaction();
            await runner.release();
        };
    });

    afterEach(async () => release());

    it('refuse une référence qui décalerait les arguments du scanner', async () => {
        await expect(controller.create({ image_name: 'nginx --privileged' }, asRequest)).rejects.toBeInstanceOf(BadRequestException);
    });

    it("rend la référence sous la forme qu'un registre attend", async () => {
        const created = await controller.create({ registry: 'ghcr.io', image_name: 'equipe/service', tag: 'v2.1.0' }, asRequest);
        expect(created.reference).toBe('ghcr.io/equipe/service:v2.1.0');

        const listed = await controller.list();
        expect(listed.find((row) => row.id === created.id)?.reference).toBe('ghcr.io/equipe/service:v2.1.0');
    });

    it("prend « latest » quand l'étiquette est absente, plutôt que d'échouer", async () => {
        const created = await controller.create({ image_name: 'nginx' }, asRequest);
        expect(created.tag).toBe('latest');
    });

    it("distingue « jamais scanné » d'un scan existant", async () => {
        const never = await manager.save(Container, Object.assign(new Container(), { imageName: 'jamais', tag: 'latest' }));
        const scanned = await manager.save(Container, Object.assign(new Container(), { imageName: 'scanne', tag: 'latest' }));
        await manager.save(Scan, Object.assign(new Scan(), { containerId: scanned.id, branch: 'n/a', status: 'completed', findingsCount: 0, createdAt: now() }));

        const listed = await controller.list();
        expect(listed.find((row) => row.id === never.id)?.lastScan).toBeNull();
        expect(listed.find((row) => row.id === scanned.id)?.lastScan?.status).toBe('completed');
    });

    it('ne compte que les problèmes à traiter', async () => {
        const container = await manager.save(Container, Object.assign(new Container(), { imageName: 'compte', tag: 'latest' }));
        for (const [index, state] of [STATE_OPEN, STATE_OPEN, STATE_RESOLVED].entries()) {
            await manager.save(
                Issue,
                Object.assign(new Issue(), {
                    containerId: container.id,
                    fingerprint: `c-${index}-${state}`,
                    type: 'vulnerability',
                    identifier: 'CVE-2026-0001',
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
        expect(listed.find((row) => row.id === container.id)?.openIssues).toBe(2);
    });

    it('rend 404 sur un conteneur inconnu plutôt que de réussir en silence', async () => {
        await expect(controller.remove(9_999_999, asRequest)).rejects.toBeInstanceOf(NotFoundException);
    });

    it('supprime le conteneur et son historique', async () => {
        const container = await manager.save(Container, Object.assign(new Container(), { imageName: 'adieu', tag: 'latest' }));
        await manager.save(Scan, Object.assign(new Scan(), { containerId: container.id, branch: 'n/a', status: 'completed', findingsCount: 0, createdAt: now() }));

        await controller.remove(container.id, asRequest);

        expect(await manager.countBy(Container, { id: container.id })).toBe(0);
        expect(await manager.countBy(Scan, { containerId: container.id })).toBe(0);
    });
});
