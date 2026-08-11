import { BadRequestException, NotFoundException } from '@nestjs/common';
import { DataSource, EntityManager } from 'typeorm';
import { now } from '../domain/common/timestamp';
import { ENTITIES, Session, User } from '../persistence/entities';
import { verifyPassword } from '../services/password.service';
import { UsersController } from './users.controller';
import type { AuthenticatedRequest } from './auth.guard';

const connectionString = process.env.ZANSHIN_TEST_DATABASE_URL;
const describeWithPostgres = connectionString ? describe : describe.skip;

const PASSWORD = 'correct-cheval-batterie';

describeWithPostgres('API des utilisateurs', () => {
    let dataSource: DataSource;
    let manager: EntityManager;
    let release: () => Promise<void>;
    let controller: UsersController;

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
        controller = new UsersController(manager);
        // Chaque suite part d'une table vide : les règles portent sur le *nombre*
        // d'administrateurs actifs, donc un compte laissé par une autre suite les fausse.
        await manager.query('DELETE FROM session');
        await manager.query('DELETE FROM "user"');
        release = async () => {
            await runner.rollbackTransaction();
            await runner.release();
        };
    });

    afterEach(async () => release());

    async function seed(username: string, role: string, isActive = true): Promise<User> {
        const createdAt = now();
        return manager.save(
            User,
            Object.assign(new User(), {
                username, role, isActive, password: null, email: null, displayName: null, avatarUrl: null,
                githubId: null, keycloakId: null, mustChangePassword: false, createdAt, updatedAt: createdAt
            })
        );
    }

    const as = (user: User) => ({ user, ip: '127.0.0.1' }) as unknown as AuthenticatedRequest;

    it("ne rend jamais l'empreinte du mot de passe", async () => {
        const admin = await seed('admin', 'ADMIN');
        await controller.create({ username: 'nouveau', password: PASSWORD }, as(admin));
        const listed = await controller.list(as(admin));
        expect(JSON.stringify(listed)).not.toContain('$2');
        expect(listed.users.every((row) => !('password' in row))).toBe(true);
    });

    it('crée un compte exigeant un changement de mot de passe', async () => {
        const admin = await seed('admin', 'ADMIN');
        const created = await controller.create({ username: 'nouveau', password: PASSWORD, role: 'user' }, as(admin));

        expect(created.role).toBe('USER');
        // Le mot de passe posé est connu de l'administrateur : c'est un laissez-passer.
        expect(created.mustChangePassword).toBe(true);
        const stored = await manager.findOneByOrFail(User, { id: created.id });
        expect(verifyPassword(PASSWORD, stored.password)).toBe(true);
    });

    it('refuse un identifiant déjà pris', async () => {
        const admin = await seed('admin', 'ADMIN');
        await expect(controller.create({ username: 'admin', password: PASSWORD }, as(admin))).rejects.toBeInstanceOf(BadRequestException);
    });

    it('refuse de se désactiver soi-même', async () => {
        const admin = await seed('admin', 'ADMIN');
        await seed('autre', 'ADMIN');
        await expect(controller.update(admin.id, { is_active: false }, as(admin))).rejects.toBeInstanceOf(BadRequestException);
    });

    it("refuse de retirer le dernier administrateur actif, même sur le compte d'un autre", async () => {
        const admin = await seed('admin', 'ADMIN');
        const autre = await seed('autre', 'ADMIN');
        // `admin` se retire lui-même du décompte ; il ne reste que `autre`.
        await controller.update(autre.id, { role: 'USER' }, as(admin));
        // Désormais `admin` est seul : le rétrograder n'a plus de repli.
        await expect(controller.update(admin.id, { role: 'USER' }, as(autre))).rejects.toBeInstanceOf(BadRequestException);
    });

    it("ferme les sessions d'un compte désactivé", async () => {
        const admin = await seed('admin', 'ADMIN');
        const cible = await seed('cible', 'USER');
        await manager.save(
            Session,
            Object.assign(new Session(), {
                token: 'jeton-de-test', userId: cible.id, createdAt: now(), lastSeenAt: now(),
                expiresAt: new Date('2099-01-01T00:00:00.000Z'), userAgent: null, ipAddress: null
            })
        );

        await controller.update(cible.id, { is_active: false }, as(admin));

        // Sans cela, « désactivé » ne veut rien dire jusqu'à l'expiration du jeton.
        expect(await manager.countBy(Session, { userId: cible.id })).toBe(0);
    });

    it('compte les sessions actives de chacun', async () => {
        const admin = await seed('admin', 'ADMIN');
        await manager.save(
            Session,
            Object.assign(new Session(), {
                token: 'jeton-admin', userId: admin.id, createdAt: now(), lastSeenAt: now(),
                expiresAt: new Date('2099-01-01T00:00:00.000Z'), userAgent: null, ipAddress: null
            })
        );
        const listed = await controller.list(as(admin));
        expect(listed.users.find((row) => row.id === admin.id)?.activeSessions).toBe(1);
        expect(listed.currentUserId).toBe(admin.id);
    });

    it('réinitialise un mot de passe et réimpose son changement', async () => {
        const admin = await seed('admin', 'ADMIN');
        const cible = await seed('cible', 'USER');
        await controller.update(cible.id, { password: 'nouveau-mot-de-passe' }, as(admin));

        const stored = await manager.findOneByOrFail(User, { id: cible.id });
        expect(verifyPassword('nouveau-mot-de-passe', stored.password)).toBe(true);
        expect(stored.mustChangePassword).toBe(true);
    });

    it('refuse un mot de passe trop court', async () => {
        const admin = await seed('admin', 'ADMIN');
        await expect(controller.create({ username: 'x', password: 'court' }, as(admin))).rejects.toBeInstanceOf(BadRequestException);
    });

    it('refuse de supprimer son propre compte', async () => {
        const admin = await seed('admin', 'ADMIN');
        await expect(controller.remove(admin.id, as(admin))).rejects.toBeInstanceOf(BadRequestException);
    });

    it('supprime un compte ordinaire et ses sessions', async () => {
        const admin = await seed('admin', 'ADMIN');
        const cible = await seed('cible', 'USER');
        await controller.remove(cible.id, as(admin));
        expect(await manager.countBy(User, { id: cible.id })).toBe(0);
    });

    it('rend 404 sur un compte inconnu', async () => {
        const admin = await seed('admin', 'ADMIN');
        await expect(controller.update(9_999_999, { role: 'USER' }, as(admin))).rejects.toBeInstanceOf(NotFoundException);
        await expect(controller.remove(9_999_999, as(admin))).rejects.toBeInstanceOf(NotFoundException);
    });
});
