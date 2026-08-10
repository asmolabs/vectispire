import { ExecutionContext, ForbiddenException, UnauthorizedException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AdminOnly, AuthGuard, PUBLIC, ROLES, Public, Roles } from './auth.guard';

/**
 * Les gardes se testent sans base : ce qu'elles décident dépend de trois choses — les
 * métadonnées de la route, ce que le service d'authentification rend, et le rôle du
 * compte. Les trois se simulent, et les enchaînements réels sont couverts par
 * `auth.integration-spec.ts`.
 */
const request = (headers: Record<string, string> = {}) => ({ headers, ip: '10.0.0.4', route: { path: '/api/v1/users' } });

function contextFor(req: object): ExecutionContext {
    return {
        switchToHttp: () => ({ getRequest: () => req }),
        getHandler: () => function handler() {},
        getClass: () => class Controller {}
    } as unknown as ExecutionContext;
}

function guardWith(options: { metadata?: Record<string, unknown>; session?: unknown; user?: unknown }) {
    const reflector = { getAllAndOverride: (key: string) => options.metadata?.[key] } as unknown as Reflector;
    const auth = { resolve: async () => options.session ?? null, revoke: async () => undefined };
    const audited: unknown[] = [];
    const audit = { record: async (_m: unknown, entry: unknown) => void audited.push(entry) };
    const manager = { findOneBy: async () => options.user ?? null };
    return { guard: new AuthGuard(reflector, auth as never, audit as never, manager as never), audited };
}

const session = { token: 'jeton', userId: 1 };
const admin = { id: 1, username: 'alice', role: 'ADMIN', isActive: true };
const plain = { ...admin, role: 'USER' };

describe('garde d’authentification', () => {
    it('laisse passer une route publique sans session', async () => {
        const { guard } = guardWith({ metadata: { [PUBLIC]: true } });
        await expect(guard.canActivate(contextFor(request()))).resolves.toBe(true);
    });

    it('refuse sans session', async () => {
        const { guard } = guardWith({});
        await expect(guard.canActivate(contextFor(request()))).rejects.toBeInstanceOf(UnauthorizedException);
    });

    it('accepte une session valide et attache l’utilisateur à la requête', async () => {
        const { guard } = guardWith({ session, user: admin });
        const req = request({ authorization: 'Bearer jeton' });

        await expect(guard.canActivate(contextFor(req))).resolves.toBe(true);
        expect((req as { user?: unknown }).user).toBe(admin);
    });

    it('refuse un compte désactivé pendant que sa session courait', async () => {
        const { guard } = guardWith({ session, user: { ...admin, isActive: false } });
        await expect(guard.canActivate(contextFor(request()))).rejects.toBeInstanceOf(UnauthorizedException);
    });

    it('refuse un compte supprimé pendant que sa session courait', async () => {
        const { guard } = guardWith({ session, user: null });
        await expect(guard.canActivate(contextFor(request()))).rejects.toBeInstanceOf(UnauthorizedException);
    });

    it("n'audite pas une session absente", async () => {
        // C'est le cas ordinaire d'un jeton expiré ; l'auditer noierait les refus qui
        // comptent.
        const { guard, audited } = guardWith({});
        await guard.canActivate(contextFor(request())).catch(() => undefined);
        expect(audited).toHaveLength(0);
    });
});

describe('garde de rôle', () => {
    it('laisse passer un rôle attendu', async () => {
        const { guard } = guardWith({ metadata: { [ROLES]: ['ADMIN', 'SUPERUSER'] }, session, user: admin });
        await expect(guard.canActivate(contextFor(request()))).resolves.toBe(true);
    });

    it('refuse un rôle insuffisant', async () => {
        const { guard } = guardWith({ metadata: { [ROLES]: ['ADMIN'] }, session, user: plain });
        await expect(guard.canActivate(contextFor(request()))).rejects.toBeInstanceOf(ForbiddenException);
    });

    it('audite le refus, avec qui, quoi et d’où', async () => {
        // Un refus n'était qu'une ligne de journal applicatif : un balayage de tous les
        // endpoints ne laissait aucune trace qu'un opérateur aurait regardée.
        const { guard, audited } = guardWith({ metadata: { [ROLES]: ['ADMIN'] }, session, user: plain });

        await guard.canActivate(contextFor(request({ 'user-agent': 'curl/8' }))).catch(() => undefined);

        expect(audited).toHaveLength(1);
        expect(audited[0]).toMatchObject({ operationType: 'ACCESS_DENIED', userId: 'alice', resourceId: '/api/v1/users', ipAddress: '10.0.0.4', userAgent: 'curl/8' });
    });

    it('une session suffit quand aucun rôle n’est exigé', async () => {
        const { guard } = guardWith({ session, user: plain });
        await expect(guard.canActivate(contextFor(request()))).resolves.toBe(true);
    });
});

describe('décorateurs', () => {
    it('AdminOnly couvre les deux rôles d’administration', () => {
        class Cible {
            @AdminOnly()
            methode() {}
        }
        expect(Reflect.getMetadata(ROLES, new Cible().methode)).toEqual(['SUPERUSER', 'ADMIN']);
    });

    it('Roles pose exactement ce qu’on lui donne', () => {
        class Cible {
            @Roles('SUPERUSER')
            methode() {}
        }
        expect(Reflect.getMetadata(ROLES, new Cible().methode)).toEqual(['SUPERUSER']);
    });

    it('Public marque la route', () => {
        class Cible {
            @Public()
            methode() {}
        }
        expect(Reflect.getMetadata(PUBLIC, new Cible().methode)).toBe(true);
    });
});
