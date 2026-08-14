import { BadRequestException, Body, Controller, Delete, Get, HttpCode, Post, Req, UnauthorizedException } from '@nestjs/common';
import { InjectEntityManager } from '@nestjs/typeorm';
import { ApiTags } from '@nestjs/swagger';
import { EntityManager } from 'typeorm';
import { Not } from 'typeorm';
import { now } from '../domain/common/timestamp';
import { validatePassword } from '../domain/users/account-rules';
import { Session, User } from '../persistence/entities';
import { AuditLogService } from '../services/audit-log.service';
import { hashPassword, verifyPassword } from '../services/password.service';
import { AuthService } from '../services/auth.service';
import { Public } from './auth.guard';
import type { AuthenticatedRequest } from './auth.guard';

/**
 * Connexion, déconnexion, et « qui suis-je ».
 *
 * L'écran de connexion n'affiche aucun identifiant par défaut, et cette API n'en
 * renvoie aucun : le compte de provisionnement porte `mustChangePassword`, ce qui est
 * la façon correcte de dire « change ton mot de passe » sans écrire lequel.
 */
@ApiTags('Authentification')
@Controller('api/v1/auth')
export class AuthController {
    constructor(
        @InjectEntityManager() private readonly manager: EntityManager,
        private readonly auth: AuthService,
        private readonly audit: AuditLogService
    ) {}

    @Public()
    @Post('login')
    @HttpCode(200)
    async login(@Body() body: Record<string, unknown>, @Req() request: AuthenticatedRequest) {
        const { outcome, audit } = await this.auth.login(this.manager, {
            username: String(body.username ?? ''),
            password: String(body.password ?? ''),
            // Le second compteur du limiteur. Jamais l'adresse IP seule : derrière un
            // NAT d'entreprise, tout le monde partagerait le même verrou.
            clientId: String(body.client_id ?? request.ip ?? 'inconnu'),
            userAgent: header(request, 'user-agent'),
            ipAddress: request.ip ?? null
        });

        await this.audit.record(this.manager, { ...audit, ipAddress: request.ip ?? null, userAgent: header(request, 'user-agent') });

        if (outcome.kind === 'blocked') {
            // 429 et non 401 : le mot de passe n'a pas été jugé, et l'appelant a besoin
            // de savoir qu'il doit attendre plutôt que réessayer.
            throw new UnauthorizedException({ message: 'Trop de tentatives. Réessayez plus tard.', retryAfterSeconds: outcome.retryAfterSeconds });
        }
        if (outcome.kind === 'invalid') {
            // Un seul message pour « compte inconnu » et « mot de passe faux » : les
            // distinguer donnerait à qui sonde la liste des comptes existants.
            throw new UnauthorizedException('Identifiants invalides.');
        }

        return {
            token: outcome.session.token,
            expiresAt: outcome.session.expiresAt,
            user: {
                username: outcome.user.username,
                displayName: outcome.user.displayName,
                role: outcome.user.role,
                mustChangePassword: outcome.user.mustChangePassword
            }
        };
    }

    @Delete('session')
    @HttpCode(204)
    async logout(@Req() request: AuthenticatedRequest): Promise<void> {
        // La ligne disparaît : la déconnexion est réelle, y compris pour un onglet
        // resté ouvert ailleurs.
        if (request.session) await this.auth.revoke(this.manager, request.session.token);
    }

    /**
     * Change son propre mot de passe.
     *
     * Le mot de passe courant est exigé même quand `mustChangePassword` est posé : sans
     * lui, un poste laissé déverrouillé une minute suffirait à s'emparer du compte. Il
     * n'y a pas d'exception « première connexion » — la personne vient précisément de
     * saisir ce mot de passe pour arriver ici.
     *
     * Les **autres** sessions du compte sont fermées. Changer son mot de passe est ce
     * qu'on fait quand on le croit compromis : laisser vivre les sessions ouvertes
     * ailleurs viderait le geste de son sens. La session courante survit, sans quoi
     * l'écran renverrait à la connexion juste après avoir réussi.
     */
    @Post('change-password')
    async changePassword(@Body() body: Record<string, unknown>, @Req() request: AuthenticatedRequest) {
        const current = String(body.current_password ?? '');
        const next = String(body.new_password ?? '');
        const user = request.user!;

        if (!verifyPassword(current, user.password)) {
            // 401 et non 400 : c'est une preuve d'identité qui manque, pas une saisie mal
            // formée, et l'écran doit pouvoir les distinguer.
            throw new UnauthorizedException('Mot de passe actuel incorrect.');
        }
        const invalid = validatePassword(next);
        if (invalid) throw new BadRequestException(invalid);
        if (next === current) {
            throw new BadRequestException("Le nouveau mot de passe est identique à l'ancien.");
        }

        await this.manager.update(
            User,
            { id: user.id },
            { password: hashPassword(next), mustChangePassword: false, updatedAt: now() }
        );
        await this.manager.delete(Session, { userId: user.id, token: Not(request.session!.token) });

        await this.audit.record(this.manager, {
            operationType: 'PASSWORD_CHANGED',
            resourceId: String(user.id),
            description: `Mot de passe changé par ${user.username}`,
            userId: user.username,
            ipAddress: request.ip ?? null
        });

        return { mustChangePassword: false };
    }

    @Get('me')
    me(@Req() request: AuthenticatedRequest) {
        const user = request.user!;
        return { username: user.username, displayName: user.displayName, role: user.role, mustChangePassword: user.mustChangePassword };
    }
}

function header(request: AuthenticatedRequest, name: string): string | null {
    const value = request.headers?.[name];
    return Array.isArray(value) ? (value[0] ?? null) : (value ?? null);
}
