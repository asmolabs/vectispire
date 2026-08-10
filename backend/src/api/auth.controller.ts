import { Body, Controller, Delete, Get, HttpCode, Post, Req, UnauthorizedException } from '@nestjs/common';
import { InjectEntityManager } from '@nestjs/typeorm';
import { EntityManager } from 'typeorm';
import { AuditLogService } from '../services/audit-log.service';
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
