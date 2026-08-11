import { BadRequestException, UnauthorizedException } from '@nestjs/common';
import { DataSource, EntityManager } from 'typeorm';
import { now } from '../domain/common/timestamp';
import { ENTITIES, Session, User } from '../persistence/entities';
import { AuditLogService } from '../services/audit-log.service';
import { AuthService } from '../services/auth.service';
import { hashPassword, verifyPassword } from '../services/password.service';
import { AuthController } from './auth.controller';
import type { AuthenticatedRequest } from './auth.guard';

const connectionString = process.env.ZANSHIN_TEST_DATABASE_URL;
const describeWithPostgres = connectionString ? describe : describe.skip;

const CURRENT = 'mot-de-passe-actuel';
const NEXT = 'nouveau-mot-de-passe-long';

describeWithPostgres('changement de mot de passe', () => {
    let dataSource: DataSource;
    let manager: EntityManager;
    let release: () => Promise<void>;
    let controller: AuthController;

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
        controller = new AuthController(manager, new AuthService(), new AuditLogService());
        release = async () => {
            await runner.rollbackTransaction();
            await runner.release();
        };
    });

    afterEach(async () => release());

    async function seed(): Promise<{ user: User; request: AuthenticatedRequest; otherToken: string }> {
        const createdAt = now();
        const user = await manager.save(
            User,
            Object.assign(new User(), {
                username: `compte-${Math.round(performance.now() * 1000)}`, role: 'USER', isActive: true,
                password: hashPassword(CURRENT), email: null, displayName: null, avatarUrl: null,
                githubId: null, keycloakId: null, mustChangePassword: true, createdAt, updatedAt: createdAt
            })
        );
        const session = (token: string) =>
            Object.assign(new Session(), {
                token, userId: user.id, createdAt, lastSeenAt: createdAt,
                expiresAt: new Date('2099-01-01T00:00:00.000Z'), userAgent: null, ipAddress: null
            });
        const current = `courante-${user.id}`;
        const other = `ailleurs-${user.id}`;
        await manager.save(Session, session(current));
        await manager.save(Session, session(other));

        return {
            user,
            request: { user, session: { token: current }, ip: '127.0.0.1' } as unknown as AuthenticatedRequest,
            otherToken: other
        };
    }

    it('change le mot de passe et lève l’obligation', async () => {
        const { user, request } = await seed();
        const result = await controller.changePassword({ current_password: CURRENT, new_password: NEXT }, request);

        expect(result.mustChangePassword).toBe(false);
        const stored = await manager.findOneByOrFail(User, { id: user.id });
        expect(verifyPassword(NEXT, stored.password)).toBe(true);
        expect(stored.mustChangePassword).toBe(false);
    });

    it('exige le mot de passe actuel même quand le changement est imposé', async () => {
        // Sans cela, un poste laissé déverrouillé une minute suffirait.
        const { request } = await seed();
        await expect(controller.changePassword({ current_password: 'faux', new_password: NEXT }, request)).rejects.toBeInstanceOf(UnauthorizedException);
    });

    it('ferme les autres sessions, et garde la courante', async () => {
        const { user, request, otherToken } = await seed();
        await controller.changePassword({ current_password: CURRENT, new_password: NEXT }, request);

        // Changer son mot de passe est ce qu'on fait quand on le croit compromis.
        expect(await manager.countBy(Session, { token: otherToken })).toBe(0);
        // Mais la session courante survit : sinon l'écran renverrait à la connexion
        // juste après avoir réussi.
        expect(await manager.countBy(Session, { userId: user.id })).toBe(1);
    });

    it('refuse un mot de passe trop court', async () => {
        const { request } = await seed();
        await expect(controller.changePassword({ current_password: CURRENT, new_password: 'court' }, request)).rejects.toBeInstanceOf(BadRequestException);
    });

    it('refuse de reposer le même mot de passe', async () => {
        const { request } = await seed();
        await expect(controller.changePassword({ current_password: CURRENT, new_password: CURRENT }, request)).rejects.toBeInstanceOf(BadRequestException);
    });

    it('inscrit le changement au journal d’audit', async () => {
        const { request } = await seed();
        await controller.changePassword({ current_password: CURRENT, new_password: NEXT }, request);

        const rows = await manager.query("SELECT description FROM audit_logs WHERE operation_type = 'PASSWORD_CHANGED'");
        expect(rows.length).toBeGreaterThan(0);
        // Le mot de passe lui-même n'a rien à faire dans le journal.
        expect(JSON.stringify(rows)).not.toContain(NEXT);
    });
});
