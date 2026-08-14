import { BadRequestException, Body, Controller, Delete, Get, HttpCode, NotFoundException, Param, Patch, Post, Req } from '@nestjs/common';
import { InjectEntityManager } from '@nestjs/typeorm';
import { ApiTags } from '@nestjs/swagger';
import { randomUUID } from 'node:crypto';
import { EntityManager } from 'typeorm';
import { generateKey, normalizeScopes } from '../domain/api-keys/api-key-rules';
import { SCOPE_AGENT } from '../domain/api-keys/scopes';
import { now } from '../domain/common/timestamp';
import { Agent, ApiKey, CREDENTIALS_DELEGATED, CREDENTIALS_LOCAL, KIND_REMOTE, ONLINE_TTL_SECONDS, Scan, STATUS_RUNNING } from '../persistence/entities';
import { AuditLogService } from '../services/audit-log.service';
import { hashPassword } from '../services/password.service';
import { AdminOnly } from './auth.guard';
import type { AuthenticatedRequest } from './auth.guard';

/**
 * L'administration des agents — distincte du protocole qu'ils parlent.
 *
 * Deux contrôleurs et non un : celui-ci exige une session d'administrateur, l'autre une
 * clé d'API d'agent. Les mêler ferait qu'une erreur d'annotation sur une route ouvrirait
 * soit l'administration aux agents, soit la file à une session ordinaire.
 */
@AdminOnly()
@ApiTags('Agents')
@Controller('api/v1/admin/agents')
export class AgentsAdminController {
    constructor(
        @InjectEntityManager() private readonly manager: EntityManager,
        private readonly audit: AuditLogService = new AuditLogService()
    ) {}

    @Get()
    async list() {
        const asOf = now();
        const [agents, running] = await Promise.all([
            this.manager.find(Agent, { order: { name: 'ASC' } }),
            this.runningByAgent()
        ]);

        return agents.map((agent) => ({
            id: agent.id,
            name: agent.name,
            description: agent.description,
            kind: agent.kind,
            enabled: agent.enabled,
            credentialsMode: agent.credentialsMode,
            maxConcurrent: agent.maxConcurrent,
            hostname: agent.hostname,
            platform: agent.platform,
            version: agent.version,
            contractVersion: agent.contractVersion,
            lastSeenAt: agent.lastSeenAt,
            /**
             * En ligne = vu récemment, et non « activé ».
             *
             * Un agent activé mais muet depuis une heure est le cas qui compte : la file se
             * remplit, personne ne la vide, et rien d'autre à l'écran ne le dirait.
             */
            online: agent.lastSeenAt !== null && asOf.getTime() - agent.lastSeenAt.getTime() < ONLINE_TTL_SECONDS * 1000,
            runningScans: running.get(agent.id) ?? 0
        }));
    }

    /**
     * Déclare un agent **et émet sa clé**, rendue une seule fois.
     *
     * Les deux ensemble parce qu'un agent sans clé ne peut rien faire : les séparer
     * laisserait une ligne inerte que l'opérateur croirait fonctionnelle.
     */
    @Post()
    async create(@Body() body: Record<string, unknown>, @Req() request: AuthenticatedRequest) {
        const name = String(body.name ?? '').trim();
        if (!name) throw new BadRequestException("Le nom de l'agent est requis.");

        const credentialsMode = String(body.credentials_mode ?? CREDENTIALS_LOCAL);
        if (![CREDENTIALS_LOCAL, CREDENTIALS_DELEGATED].includes(credentialsMode)) {
            throw new BadRequestException(`Mode d'identifiants inconnu : « ${credentialsMode} ».`);
        }

        const { fullKey, prefix } = generateKey();
        const keyId = randomUUID();
        const at = now();

        await this.manager.save(
            ApiKey,
            Object.assign(new ApiKey(), {
                id: keyId,
                name: `Agent ${name}`,
                keyHash: hashPassword(fullKey),
                prefix,
                // Le seul périmètre : un agent n'a pas à lire le backlog ni à exporter.
                scopes: normalizeScopes([SCOPE_AGENT]).join(','),
                targetKind: null,
                targetId: null,
                createdAt: at,
                lastUsedAt: null,
                expiresAt: null
            })
        );

        const agent = await this.manager.save(
            Agent,
            Object.assign(new Agent(), {
                name,
                description: asText(body.description),
                kind: KIND_REMOTE,
                credentialsMode,
                enabled: true,
                maxConcurrent: body.max_concurrent == null ? 1 : Number(body.max_concurrent),
                apiKeyId: keyId,
                createdAt: at
            })
        );

        await this.audit.record(this.manager, {
            operationType: 'SETTING_UPDATED',
            resourceId: agent.id,
            description: `Agent déclaré : ${name} (${credentialsMode})`,
            userId: request.user?.username ?? null,
            ipAddress: request.ip ?? null
        });

        // La seule occurrence de la clé en clair. Elle ne réapparaîtra jamais.
        return { id: agent.id, name: agent.name, secret: fullKey };
    }

    /** Active ou désactive. Un agent désactivé ne réclame plus, sans perdre son histoire. */
    @Patch(':id')
    async update(@Param('id') id: string, @Body() body: Record<string, unknown>, @Req() request: AuthenticatedRequest) {
        const agent = await this.manager.findOneBy(Agent, { id });
        if (!agent) throw new NotFoundException('Agent introuvable.');

        const enabled = body.enabled === undefined ? agent.enabled : Boolean(body.enabled);
        await this.manager.update(Agent, { id }, { enabled, maxConcurrent: body.max_concurrent == null ? agent.maxConcurrent : Number(body.max_concurrent) });

        if (enabled !== agent.enabled) {
            await this.audit.record(this.manager, {
                operationType: 'SETTING_UPDATED',
                resourceId: id,
                description: `Agent ${agent.name} ${enabled ? 'réactivé' : 'désactivé'}`,
                userId: request.user?.username ?? null,
                ipAddress: request.ip ?? null
            });
        }
        return { id, enabled };
    }

    @Delete(':id')
    @HttpCode(204)
    async remove(@Param('id') id: string, @Req() request: AuthenticatedRequest): Promise<void> {
        const agent = await this.manager.findOneBy(Agent, { id });
        if (!agent) throw new NotFoundException('Agent introuvable.');

        const running = await this.manager.countBy(Scan, { claimedBy: id, status: STATUS_RUNNING });
        if (running > 0) {
            // Supprimer maintenant laisserait ces scans sans propriétaire jusqu'à
            // expiration de leur bail, et l'opérateur les verrait « en cours » sans savoir
            // que personne ne les mène.
            throw new BadRequestException(`Cet agent exécute ${running} scan(s). Désactivez-le et attendez qu'il termine.`);
        }

        await this.manager.delete(Agent, { id });
        // La clé part avec : la garder ouvrirait un accès au protocole sans agent derrière.
        if (agent.apiKeyId) await this.manager.delete(ApiKey, { id: agent.apiKeyId });

        await this.audit.record(this.manager, {
            operationType: 'SETTING_UPDATED',
            resourceId: id,
            description: `Agent supprimé : ${agent.name}`,
            userId: request.user?.username ?? null,
            ipAddress: request.ip ?? null
        });
    }

    private async runningByAgent(): Promise<Map<string, number>> {
        const rows: { claimedBy: string; count: string }[] = await this.manager
            .createQueryBuilder(Scan, 'scan')
            .select('scan.claimed_by', 'claimedBy')
            .addSelect('COUNT(*)', 'count')
            .where('scan.status = :status', { status: STATUS_RUNNING })
            .andWhere('scan.claimed_by IS NOT NULL')
            .groupBy('scan.claimed_by')
            .getRawMany();
        return new Map(rows.map((row) => [row.claimedBy, Number(row.count)]));
    }
}

function asText(value: unknown): string | null {
    const text = typeof value === 'string' ? value.trim() : '';
    return text || null;
}
