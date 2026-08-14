import { DataSource, EntityManager } from 'typeorm';
import { ExecutionContext, ForbiddenException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { now } from '../domain/common/timestamp';
import { Session, User } from '../persistence/entities';
import { hashPassword } from '../services/password.service';
import { AuditLogService } from '../services/audit-log.service';
import { ApiKeyAuthService } from '../services/api-key-auth.service';
import { AuthService } from '../services/auth.service';
import { AllowsPendingPasswordChange, AuthGuard, Public } from './auth.guard';
import { connectToTestDatabase } from '../../test/database';

/**
 * Le changement de mot de passe imposé, vérifié **côté serveur**.
 *
 * Le drapeau `mustChangePassword` était posé à trois endroits — le compte d'amorçage, la
 * création d'un utilisateur, la réinitialisation par un administrateur — et lu par
 * personne d'autre que le client Angular. Ce n'était donc pas un contrôle : un appel
 * direct à l'API l'ignorait, et le mot de passe d'amorçage — qui vit dans la configuration
 * du déploiement, les journaux d'orchestrateur et l'historique du shell — restait un
 * identifiant SUPERUSER pleinement valable et sans expiration.
 *
 * Ces tests passent par la garde elle-même : c'est le seul endroit où la réponse est la
 * même pour toutes les routes.
 */
describe('garde du changement de mot de passe', () => {
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

    function guard(): AuthGuard {
        return new AuthGuard(new Reflector(), new ApiKeyAuthService(), new AuthService(), new AuditLogService(), manager);
    }

    /** Un compte et une session ouverte, comme après une connexion réussie. */
    async function signedIn(mustChangePassword: boolean): Promise<string> {
        const moment = now();
        const user = await manager.save(
            Object.assign(new User(), {
                username: `u${Math.random().toString(36).slice(2, 9)}`,
                email: null,
                password: hashPassword('motdepasse-solide'),
                displayName: null,
                avatarUrl: null,
                role: 'SUPERUSER',
                isActive: true,
                githubId: null,
                keycloakId: null,
                createdAt: moment,
                updatedAt: moment,
                mustChangePassword
            })
        );

        const token = `jeton-${Math.random().toString(36).slice(2)}`;
        await manager.save(
            Object.assign(new Session(), {
                token,
                userId: user.id,
                createdAt: moment,
                lastSeenAt: moment,
                expiresAt: new Date(moment.getTime() + 3_600_000),
                userAgent: null,
                ipAddress: null
            })
        );
        return token;
    }

    /** Un contexte d'exécution portant les annotations demandées. */
    function context(token: string, decorators: (() => MethodDecorator | ClassDecorator)[] = []): ExecutionContext {
        class Cible {
            handler(): void {}
        }
        for (const decorate of decorators) {
            (decorate() as MethodDecorator)(Cible.prototype, 'handler', Object.getOwnPropertyDescriptor(Cible.prototype, 'handler')!);
        }

        return {
            switchToHttp: () => ({ getRequest: () => ({ headers: { authorization: `Bearer ${token}` }, ip: null }) }),
            getHandler: () => Cible.prototype.handler,
            getClass: () => Cible
        } as unknown as ExecutionContext;
    }

    it('refuse toute route ordinaire tant que le mot de passe doit changer', async () => {
        // Le cœur du sujet : sans cette vérification, le compte d'amorçage ouvrait
        // l'intégralité de l'API — utilisateurs, clés d'API, agents, réglages, audit.
        const token = await signedIn(true);

        await expect(guard().canActivate(context(token))).rejects.toBeInstanceOf(ForbiddenException);
    });

    it('laisse passer les routes qui permettent d’en sortir', async () => {
        // Refuser aussi celles-ci enfermerait le compte : il faut pouvoir lire son profil,
        // changer le mot de passe, et se déconnecter.
        const token = await signedIn(true);

        expect(await guard().canActivate(context(token, [AllowsPendingPasswordChange]))).toBe(true);
    });

    it('ne gêne pas un compte dont le mot de passe est à jour', async () => {
        const token = await signedIn(false);

        expect(await guard().canActivate(context(token))).toBe(true);
    });

    it("n'interfère pas avec les routes publiques", async () => {
        // La connexion elle-même doit rester joignable, sans quoi le compte ne pourrait
        // même pas obtenir la session qui lui permettra de changer son mot de passe.
        const token = await signedIn(true);

        expect(await guard().canActivate(context(token, [Public]))).toBe(true);
    });
});
