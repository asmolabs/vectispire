import { BadRequestException, Body, Controller, Delete, Get, HttpCode, NotFoundException, Param, ParseIntPipe, Patch, Post, Req } from '@nestjs/common';
import { InjectEntityManager } from '@nestjs/typeorm';
import { ApiTags } from '@nestjs/swagger';
import { EntityManager, Not } from 'typeorm';
import { now } from '../domain/common/timestamp';
import { isAdminRole, refuseDeletion, refuseSelfLockout, validatePassword, validateRole, validateUsername } from '../domain/users/account-rules';
import { ADMIN_ROLES, Session, User } from '../persistence/entities';
import { AuditLogService } from '../services/audit-log.service';
import { hashPassword } from '../services/password.service';
import { AdminOnly } from './auth.guard';
import type { AuthenticatedRequest } from './auth.guard';

/** Ce qu'un compte montre. `password` n'y figure pas, et ne doit jamais y figurer :
 *  une empreinte bcrypt qui sort du serveur est une empreinte à casser hors ligne. */
function toSummary(user: User, activeSessions: number) {
    return {
        id: user.id,
        username: user.username,
        email: user.email,
        displayName: user.displayName,
        role: user.role,
        isActive: user.isActive,
        mustChangePassword: user.mustChangePassword,
        createdAt: user.createdAt,
        activeSessions
    };
}

@AdminOnly()
@ApiTags('Administration')
@Controller('api/v1/users')
export class UsersController {
    constructor(
        @InjectEntityManager() private readonly manager: EntityManager,
        private readonly audit: AuditLogService = new AuditLogService()
    ) {}

    @Get()
    async list(@Req() request: AuthenticatedRequest) {
        const [users, sessions] = await Promise.all([
            this.manager.find(User, { order: { username: 'ASC' } }),
            this.activeSessionsByUser()
        ]);
        return {
            users: users.map((user) => toSummary(user, sessions.get(user.id) ?? 0)),
            // L'écran a besoin de savoir quel compte est le sien pour ne pas proposer
            // des actions que le serveur refusera de toute façon.
            currentUserId: request.user?.id ?? null
        };
    }

    @Post()
    async create(@Body() body: Record<string, unknown>, @Req() request: AuthenticatedRequest) {
        const username = String(body.username ?? '').trim();
        const password = String(body.password ?? '');
        const role = String(body.role ?? 'USER').trim().toUpperCase();

        for (const message of [validateUsername(username), validatePassword(password), validateRole(role)]) {
            if (message) throw new BadRequestException(message);
        }
        if (await this.manager.countBy(User, { username })) {
            throw new BadRequestException(`L'identifiant « ${username} » est déjà pris.`);
        }

        const createdAt = now();
        const saved = await this.manager.save(
            User,
            Object.assign(new User(), {
                username,
                email: asOptional(body.email),
                displayName: asOptional(body.display_name),
                password: hashPassword(password),
                role,
                isActive: true,
                // Le mot de passe posé ici est connu de l'administrateur qui l'a saisi :
                // il tient lieu de laissez-passer, pas de secret du compte.
                mustChangePassword: true,
                githubId: null,
                keycloakId: null,
                avatarUrl: null,
                createdAt,
                updatedAt: createdAt
            })
        );

        await this.record(request, saved.id, `Compte créé : ${username} (${role})`);
        return toSummary(saved, 0);
    }

    /** Rôle, activation, et réinitialisation du mot de passe — les trois portent les
     *  mêmes garde-fous, donc un seul point d'entrée plutôt que trois à garder alignés. */
    @Patch(':id')
    async update(@Param('id', ParseIntPipe) id: number, @Body() body: Record<string, unknown>, @Req() request: AuthenticatedRequest) {
        const user = await this.manager.findOneBy(User, { id });
        if (!user) throw new NotFoundException('Compte introuvable.');

        const role = body.role === undefined ? user.role : String(body.role).trim().toUpperCase();
        const isActive = body.is_active === undefined ? user.isActive : Boolean(body.is_active);
        const password = body.password === undefined ? null : String(body.password);

        const invalidRole = validateRole(role);
        if (invalidRole) throw new BadRequestException(invalidRole);
        if (password !== null) {
            const invalid = validatePassword(password);
            if (invalid) throw new BadRequestException(invalid);
        }

        const refusal = refuseSelfLockout({
            isSelf: request.user?.id === id,
            wasAdmin: isAdminRole(user.role) && user.isActive,
            willBeAdmin: isAdminRole(role),
            willBeActive: isActive,
            remainingActiveAdmins: await this.countOtherActiveAdmins(id)
        });
        if (refusal) throw new BadRequestException(refusal);

        const changes: string[] = [];
        const previousRole = user.role;
        if (role !== user.role) changes.push(`rôle ${user.role} → ${role}`);
        if (isActive !== user.isActive) changes.push(isActive ? 'réactivé' : 'désactivé');
        if (password !== null) changes.push('mot de passe réinitialisé');

        Object.assign(user, {
            role,
            isActive,
            updatedAt: now(),
            ...(password !== null ? { password: hashPassword(password), mustChangePassword: true } : {})
        });
        await this.manager.save(User, user);

        // **Trois gestes ferment les sessions, pas un seul.**
        //
        // Désactiver, bien sûr : sinon le compte reste dedans jusqu'à expiration et
        // « désactivé » ne veut plus rien dire.
        //
        // Mais réinitialiser un mot de passe aussi, et c'est celui qui manquait — c'est
        // pourtant le geste de la réponse à incident. Un administrateur à qui l'on signale
        // un jeton volé réinitialise le mot de passe, l'écran confirme, et le jeton volé
        // continue d'authentifier jusqu'à douze heures, sa fenêtre d'inactivité repoussée
        // à chaque appel. Le mot de passe change, l'accès non.
        //
        // Et changer de rôle : une session ouverte porte le rôle relu à chaque requête,
        // donc une rétrogradation prend effet — mais fermer la session rend la chose
        // explicite plutôt que dépendante de ce détail.
        const revoke = !isActive || password !== null || role !== previousRole;
        if (revoke) await this.manager.delete(Session, { userId: id });

        if (changes.length) await this.record(request, id, `Compte ${user.username} : ${changes.join(', ')}`);
        return toSummary(user, revoke ? 0 : (await this.activeSessionsByUser()).get(id) ?? 0);
    }

    @Delete(':id')
    @HttpCode(204)
    async remove(@Param('id', ParseIntPipe) id: number, @Req() request: AuthenticatedRequest): Promise<void> {
        const user = await this.manager.findOneBy(User, { id });
        if (!user) throw new NotFoundException('Compte introuvable.');

        const refusal = refuseDeletion({
            isSelf: request.user?.id === id,
            isAdmin: isAdminRole(user.role) && user.isActive,
            remainingActiveAdmins: await this.countOtherActiveAdmins(id)
        });
        if (refusal) throw new BadRequestException(refusal);

        await this.manager.delete(Session, { userId: id });
        await this.manager.delete(User, { id });
        await this.record(request, id, `Compte supprimé : ${user.username}`);
    }

    private async countOtherActiveAdmins(excludedId: number): Promise<number> {
        return this.manager
            .createQueryBuilder(User, 'user')
            .where('user.id != :excludedId', { excludedId })
            .andWhere('user.is_active = true')
            .andWhere('user.role IN (:...roles)', { roles: [...ADMIN_ROLES] })
            .getCount();
    }

    private async activeSessionsByUser(): Promise<Map<number, number>> {
        const rows: { userId: string; count: string }[] = await this.manager
            .createQueryBuilder(Session, 'session')
            .select('session.user_id', 'userId')
            .addSelect('COUNT(*)', 'count')
            .where('session.expires_at > :now', { now: now() })
            .groupBy('session.user_id')
            .getRawMany();
        return new Map(rows.map((row) => [Number(row.userId), Number(row.count)]));
    }

    private async record(request: AuthenticatedRequest, resourceId: number, description: string): Promise<void> {
        await this.audit.record(this.manager, {
            operationType: 'SETTING_UPDATED',
            resourceId: String(resourceId),
            description,
            userId: request.user?.username ?? null,
            ipAddress: request.ip ?? null
        });
    }
}

function asOptional(value: unknown): string | null {
    const text = typeof value === 'string' ? value.trim() : '';
    return text || null;
}
