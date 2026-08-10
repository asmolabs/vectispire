import { CanActivate, ExecutionContext, ForbiddenException, Injectable, SetMetadata, UnauthorizedException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { EntityManager } from 'typeorm';
import { InjectEntityManager } from '@nestjs/typeorm';
import { ADMIN_ROLES, Session, User } from '../persistence/entities';
import { AuditLogService } from '../services/audit-log.service';
import { AuthService } from '../services/auth.service';

/**
 * Les gardes d'accès.
 *
 * **Ce qu'elles remplacent.** En Reflex, chaque gestionnaire d'évènement d'une classe
 * d'état est adressable individuellement par websocket : une vérification posée au
 * montage de la page protégeait le rendu, pas les gestionnaires. D'où les décorateurs
 * `@requires_login` / `@requires_admin` posés sur *chaque* méthode touchant la base, et
 * les quatre variantes d'enveloppe qu'il fallait écrire pour couvrir les fonctions
 * planes, les coroutines et les deux sortes de générateurs.
 *
 * Ce problème disparaît : une route HTTP a un seul point d'entrée, et une garde s'y
 * applique. Ce qui ne disparaît pas, c'est la règle qu'il portait — **l'autorisation
 * s'applique au point d'entrée, jamais au rendu**.
 *
 * Ce qui reste aussi, c'est l'audit du refus. Un refus d'autorisation n'était qu'une
 * ligne de journal applicatif, si bien qu'un balayage de tous les endpoints ne laissait
 * aucune trace qu'un opérateur aurait un jour regardée.
 */

/** Marque une route comme accessible sans session. */
export const PUBLIC = 'zanshin:public';
export const Public = () => SetMetadata(PUBLIC, true);

/** Restreint une route à certains rôles. Sans elle, une session suffit. */
export const ROLES = 'zanshin:roles';
export const Roles = (...roles: string[]) => SetMetadata(ROLES, roles);

/** Réserve une route aux administrateurs. */
export const AdminOnly = () => Roles(...ADMIN_ROLES);

export interface AuthenticatedRequest {
    session?: Session;
    user?: User;
    headers: Record<string, string | string[] | undefined>;
    ip?: string;
    route?: { path?: string };
}

@Injectable()
export class AuthGuard implements CanActivate {
    constructor(
        private readonly reflector: Reflector,
        private readonly auth: AuthService,
        private readonly audit: AuditLogService,
        @InjectEntityManager() private readonly manager: EntityManager
    ) {}

    async canActivate(context: ExecutionContext): Promise<boolean> {
        // `getAllAndOverride` : une annotation sur la méthode l'emporte sur celle du
        // contrôleur. Sans cela, un contrôleur marqué public rendrait publiques des
        // routes qui ne le sont pas.
        const isPublic = this.reflector.getAllAndOverride<boolean>(PUBLIC, [context.getHandler(), context.getClass()]);
        if (isPublic) return true;

        const request = context.switchToHttp().getRequest<AuthenticatedRequest>();
        const session = await this.auth.resolve(this.manager, headerValue(request, 'authorization'));
        if (!session) {
            // Pas d'audit ici : une requête sans session valide est le cas ordinaire
            // d'un jeton expiré, et l'auditer noierait les refus qui comptent.
            throw new UnauthorizedException('Session absente ou expirée.');
        }

        const user = await this.manager.findOneBy(User, { id: session.userId });
        if (!user || !user.isActive) {
            // Le compte a été désactivé ou supprimé pendant que la session courait.
            await this.auth.revoke(this.manager, session.token);
            throw new UnauthorizedException('Session absente ou expirée.');
        }

        request.session = session;
        request.user = user;

        const required = this.reflector.getAllAndOverride<string[]>(ROLES, [context.getHandler(), context.getClass()]);
        if (required?.length && !required.includes(user.role)) {
            await this.audit.record(this.manager, {
                operationType: 'ACCESS_DENIED',
                resourceId: request.route?.path ?? 'inconnu',
                description: `Accès refusé : rôle ${user.role}, requis ${required.join(' ou ')}`,
                userId: user.username,
                ipAddress: request.ip ?? null,
                userAgent: headerValue(request, 'user-agent')
            });
            throw new ForbiddenException("Vous n'avez pas les droits nécessaires.");
        }

        return true;
    }
}

function headerValue(request: AuthenticatedRequest, name: string): string | null {
    const value = request.headers?.[name];
    return Array.isArray(value) ? (value[0] ?? null) : (value ?? null);
}
