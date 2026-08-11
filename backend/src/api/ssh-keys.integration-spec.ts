import { BadRequestException, NotFoundException } from '@nestjs/common';
import { DataSource, EntityManager } from 'typeorm';
import { now } from '../domain/common/timestamp';
import { encryptWith, deriveKey, privateKeyContext } from '../domain/crypto/encryption';
import { ENTITIES, Repository as GitRepository, SshKey } from '../persistence/entities';
import { EncryptionService } from '../services/encryption.service';
import { SshKeysController } from './ssh-keys.controller';
import type { AuthenticatedRequest } from './auth.guard';

const connectionString = process.env.ZANSHIN_TEST_DATABASE_URL;
const describeWithPostgres = connectionString ? describe : describe.skip;

const CURRENT = 'cle-courante-de-test-32-octets!!!';
const PREVIOUS = 'ancienne-cle-de-test';
const PRIVATE = '-----BEGIN OPENSSH PRIVATE KEY-----\nfaux\n-----END OPENSSH PRIVATE KEY-----\n';
const asRequest = { user: { username: 'admin', role: 'ADMIN' }, ip: '127.0.0.1' } as unknown as AuthenticatedRequest;

describeWithPostgres('API des clés SSH', () => {
    let dataSource: DataSource;
    let manager: EntityManager;
    let release: () => Promise<void>;
    let controller: SshKeysController;
    const encryption = new EncryptionService(CURRENT, [PREVIOUS]);

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
        controller = new SshKeysController(manager, encryption);
        release = async () => {
            await runner.rollbackTransaction();
            await runner.release();
        };
    });

    afterEach(async () => release());

    it('ne rend jamais la moitié privée', async () => {
        await controller.create({ name: 'déploiement', private_key: PRIVATE, public_key: 'ssh-rsa AAAA' }, asRequest);
        const listed = await controller.list();
        expect(JSON.stringify(listed)).not.toContain('PRIVATE KEY');
        expect(listed.every((row) => !('privateKey' in row))).toBe(true);
    });

    it('chiffre la clé privée en base, liée à sa ligne', async () => {
        const created = await controller.create({ name: 'liée', private_key: PRIVATE }, asRequest);
        const stored = await manager.findOneByOrFail(SshKey, { id: created.id });

        expect(stored.privateKey).not.toContain('PRIVATE KEY');
        expect(encryption.inspect(stored.privateKey, privateKeyContext(created.id)).plainText).toBe(PRIVATE.trim());
        // Le même chiffré présenté comme appartenant à une autre ligne ne doit rien rendre.
        expect(encryption.inspect(stored.privateKey, privateKeyContext('00000000-0000-0000-0000-000000000000')).state).toBe('unreadable');
    });

    it('signale une clé restée sous une clé de chiffrement précédente', async () => {
        const id = '33333333-3333-3333-3333-333333333333';
        await manager.save(
            SshKey,
            Object.assign(new SshKey(), {
                id,
                name: 'à faire tourner',
                privateKey: encryptWith(deriveKey(PREVIOUS), PRIVATE, privateKeyContext(id)),
                publicKey: null,
                createdAt: now()
            })
        );
        expect((await controller.list()).find((row) => row.id === id)?.encryptionState).toBe('previous_key');
    });

    it("signale une clé qu'aucune clé configurée ne lit, plutôt que d'échouer au prochain clone", async () => {
        const id = '44444444-4444-4444-4444-444444444444';
        await manager.save(
            SshKey,
            Object.assign(new SshKey(), {
                id,
                name: 'perdue',
                privateKey: encryptWith(deriveKey('une-clé-que-personne-n-a'), PRIVATE, privateKeyContext(id)),
                publicKey: null,
                createdAt: now()
            })
        );
        expect((await controller.list()).find((row) => row.id === id)?.encryptionState).toBe('unreadable');
    });

    it("refuse ce qui n'est pas une clé privée, à la saisie et non au premier clone", async () => {
        await expect(controller.create({ name: 'x', private_key: 'mon mot de passe' }, asRequest)).rejects.toBeInstanceOf(BadRequestException);
    });

    it("refuse d'écrire quand aucune clé de chiffrement n'est configurée", async () => {
        const unconfigured = new SshKeysController(manager, new EncryptionService(null, []));
        await expect(unconfigured.create({ name: 'x', private_key: PRIVATE }, asRequest)).rejects.toBeInstanceOf(BadRequestException);
    });

    it('refuse de supprimer une clé encore utilisée par un dépôt', async () => {
        const created = await controller.create({ name: 'utilisée', private_key: PRIVATE }, asRequest);
        await manager.save(GitRepository, Object.assign(new GitRepository(), { url: 'git@x:y/z.git', branch: 'main', sshKeyId: created.id }));

        // Sinon l'échec arriverait au prochain scan, loin d'ici.
        await expect(controller.remove(created.id, asRequest)).rejects.toBeInstanceOf(BadRequestException);
        expect(await manager.countBy(SshKey, { id: created.id })).toBe(1);
    });

    it('supprime une clé libre', async () => {
        const created = await controller.create({ name: 'libre', private_key: PRIVATE }, asRequest);
        await controller.remove(created.id, asRequest);
        expect(await manager.countBy(SshKey, { id: created.id })).toBe(0);
    });

    it('rend 404 sur une clé inconnue', async () => {
        await expect(controller.remove('55555555-5555-5555-5555-555555555555', asRequest)).rejects.toBeInstanceOf(NotFoundException);
    });
});
