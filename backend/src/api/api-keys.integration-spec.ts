import { BadRequestException, NotFoundException } from '@nestjs/common';
import { DataSource, EntityManager } from 'typeorm';
import { now } from '../domain/common/timestamp';
import { ApiKey, Container, ENTITIES, Repository as GitRepository } from '../persistence/entities';
import { verifyPassword } from '../services/password.service';
import { ApiKeysController } from './api-keys.controller';
import type { AuthenticatedRequest } from './auth.guard';

const connectionString = process.env.ZANSHIN_TEST_DATABASE_URL;
const describeWithPostgres = connectionString ? describe : describe.skip;

const asRequest = { user: { username: 'admin', role: 'ADMIN' }, ip: '127.0.0.1' } as unknown as AuthenticatedRequest;

describeWithPostgres("API des clés d'API", () => {
    let dataSource: DataSource;
    let manager: EntityManager;
    let release: () => Promise<void>;
    let controller: ApiKeysController;

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
        controller = new ApiKeysController(manager);
        await manager.query('DELETE FROM api_key');
        release = async () => {
            await runner.rollbackTransaction();
            await runner.release();
        };
    });

    afterEach(async () => release());

    it('rend la valeur en clair une seule fois, et ne la stocke pas', async () => {
        const { key, secret } = await controller.create({ name: 'chaîne CI' }, asRequest);

        expect(secret).toMatch(/^zsk_[A-Za-z0-9_-]{43}$/);
        const stored = await manager.findOneByOrFail(ApiKey, { id: key.id });
        expect(stored.keyHash).not.toContain(secret);
        expect(verifyPassword(secret, stored.keyHash)).toBe(true);

        // La liste ne la rend plus, et rien ne permet de la retrouver.
        const listed = await controller.list();
        expect(JSON.stringify(listed)).not.toContain(secret);
        expect(JSON.stringify(listed)).not.toContain(stored.keyHash);
    });

    it('garde le préfixe en clair, pour ne pas payer un bcrypt par clé existante', async () => {
        const { key, secret } = await controller.create({ name: 'préfixe' }, asRequest);
        expect(key.prefix).toBe(secret.slice(0, 12));
        expect(key.prefix).toHaveLength(12);
    });

    it("n'accorde jamais « agent » par défaut", async () => {
        const { key } = await controller.create({ name: 'défauts' }, asRequest);
        expect(key.scopes).toEqual(['read', 'scan', 'export']);
    });

    it('accepte « agent » quand il est demandé explicitement', async () => {
        const { key } = await controller.create({ name: 'agent', scopes: ['read', 'agent'] }, asRequest);
        expect(key.scopes).toEqual(['read', 'agent']);
    });

    it('refuse une portée inconnue plutôt que de l’ignorer', async () => {
        await expect(controller.create({ name: 'x', scopes: ['read', 'admin'] }, asRequest)).rejects.toBeInstanceOf(BadRequestException);
    });

    it('restreint à une cible existante et en affiche le nom', async () => {
        const repository = await manager.save(GitRepository, Object.assign(new GitRepository(), { url: 'https://github.com/org/api.git', branch: 'main', name: 'org/api' }));
        const { key } = await controller.create({ name: 'bornée', target_kind: 'repository', target_id: repository.id }, asRequest);

        expect(key.targetKind).toBe('repository');
        // Le nom plutôt que l'identifiant : un identifiant ne dit rien à l'écran.
        expect(key.targetLabel).toBe('org/api');
    });

    it("refuse une restriction vers une cible inexistante, plutôt que d'attendre le premier appel", async () => {
        await expect(controller.create({ name: 'x', target_kind: 'repository', target_id: 9_999_999 }, asRequest)).rejects.toBeInstanceOf(BadRequestException);
    });

    it('refuse une moitié de restriction', async () => {
        await expect(controller.create({ name: 'x', target_kind: 'repository' }, asRequest)).rejects.toBeInstanceOf(BadRequestException);
    });

    it('dit qu’une cible a été supprimée depuis l’émission', async () => {
        const container = await manager.save(Container, Object.assign(new Container(), { imageName: 'nginx', tag: 'latest' }));
        const { key } = await controller.create({ name: 'orpheline', target_kind: 'container', target_id: container.id }, asRequest);
        await manager.delete(Container, { id: container.id });

        const listed = await controller.list();
        expect(listed.find((row) => row.id === key.id)?.targetLabel).toMatch(/supprimée/);
    });

    it('calcule l’expiration côté serveur', async () => {
        const { key } = await controller.create({ name: 'temporaire', expires_in_days: 30 }, asRequest);
        expect(key.expiresAt).not.toBeNull();
        expect(key.isExpired).toBe(false);

        const expired = await manager.save(
            ApiKey,
            Object.assign(new ApiKey(), {
                id: '66666666-6666-6666-6666-666666666666', name: 'périmée', keyHash: 'peu importe', prefix: 'zsk_aaaaaaaa',
                scopes: 'read', targetKind: null, targetId: null, createdAt: now(), lastUsedAt: null,
                expiresAt: new Date('2020-01-01T00:00:00.000Z')
            })
        );
        const listed = await controller.list();
        expect(listed.find((row) => row.id === expired.id)?.isExpired).toBe(true);
    });

    it('refuse une durée de vie absurde', async () => {
        await expect(controller.create({ name: 'x', expires_in_days: 0 }, asRequest)).rejects.toBeInstanceOf(BadRequestException);
    });

    it('révoque en supprimant la ligne', async () => {
        const { key } = await controller.create({ name: 'à révoquer' }, asRequest);
        await controller.remove(key.id, asRequest);
        expect(await manager.countBy(ApiKey, { id: key.id })).toBe(0);
    });

    it('rend 404 sur une clé inconnue', async () => {
        await expect(controller.remove('77777777-7777-7777-7777-777777777777', asRequest)).rejects.toBeInstanceOf(NotFoundException);
    });
});
