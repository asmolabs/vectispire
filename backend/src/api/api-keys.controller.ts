import { BadRequestException, Body, Controller, Delete, Get, HttpCode, NotFoundException, Param, Post, Req } from '@nestjs/common';
import { InjectEntityManager } from '@nestjs/typeorm';
import { randomUUID } from 'node:crypto';
import { EntityManager } from 'typeorm';
import { generateKey, InvalidApiKeyError, normalizeLifetime, normalizeScopes, normalizeTarget } from '../domain/api-keys/api-key-rules';
import { now } from '../domain/common/timestamp';
import { ApiKey, Container, Repository as GitRepository } from '../persistence/entities';
import { AuditLogService } from '../services/audit-log.service';
import { hashPassword } from '../services/password.service';
import { AdminOnly } from './auth.guard';
import type { AuthenticatedRequest } from './auth.guard';

/** Ce qu'une clé montre. `keyHash` n'y figure pas ; `prefix` oui, il n'est pas secret. */
function toSummary(key: ApiKey, asOf: Date, targetLabel: string | null) {
    return {
        id: key.id,
        name: key.name,
        prefix: key.prefix,
        scopes: key.scopes ? key.scopes.split(',') : [],
        targetKind: key.targetKind,
        targetId: key.targetId,
        targetLabel,
        createdAt: key.createdAt,
        lastUsedAt: key.lastUsedAt,
        expiresAt: key.expiresAt,
        // Calculé ici et non à l'écran : une clé expirée est refusée par le serveur, et
        // deux notions d'« expirée » finiraient par diverger d'un fuseau horaire.
        isExpired: key.expiresAt !== null && key.expiresAt <= asOf
    };
}

@AdminOnly()
@Controller('api/v1/api-keys')
export class ApiKeysController {
    constructor(
        @InjectEntityManager() private readonly manager: EntityManager,
        private readonly audit: AuditLogService = new AuditLogService()
    ) {}

    @Get()
    async list() {
        const asOf = now();
        const [keys, labels] = await Promise.all([
            this.manager.find(ApiKey, { order: { createdAt: 'DESC' } }),
            this.targetLabels()
        ]);
        return keys.map((key) => toSummary(key, asOf, this.labelFor(key, labels)));
    }

    /**
     * Émet une clé et **la rend une seule fois**.
     *
     * C'est le seul endroit où la valeur en clair existe. Une implémentation antérieure
     * affichait en permanence l'identifiant de la ligne comme s'il était le secret — donc
     * il n'y avait jamais eu de secret. La rendre irrécupérable est le point.
     */
    @Post()
    async create(@Body() body: Record<string, unknown>, @Req() request: AuthenticatedRequest) {
        const name = String(body.name ?? '').trim();
        if (!name) throw new BadRequestException('Le nom est requis.');

        let scopes: string[];
        let target: { targetKind: string | null; targetId: number | null };
        let lifetime: number | null;
        try {
            scopes = normalizeScopes(Array.isArray(body.scopes) ? (body.scopes as string[]) : null);
            target = normalizeTarget(body.target_kind, body.target_id);
            lifetime = normalizeLifetime(body.expires_in_days);
        } catch (error) {
            if (error instanceof InvalidApiKeyError) throw new BadRequestException(error.message);
            throw error;
        }

        if (target.targetKind !== null) await this.assertTargetExists(target.targetKind, target.targetId!);

        const { fullKey, prefix } = generateKey();
        const issuedAt = now();
        const saved = await this.manager.save(
            ApiKey,
            Object.assign(new ApiKey(), {
                id: randomUUID(),
                name,
                keyHash: hashPassword(fullKey),
                prefix,
                scopes: scopes.join(','),
                ...target,
                createdAt: issuedAt,
                lastUsedAt: null,
                expiresAt: lifetime === null ? null : addDays(issuedAt, lifetime)
            })
        );

        await this.audit.record(this.manager, {
            operationType: 'SETTING_UPDATED',
            resourceId: saved.id,
            description: `Clé d'API émise : ${name} (${scopes.join(', ')}${target.targetKind ? `, ${target.targetKind} ${target.targetId}` : ''})`,
            userId: request.user?.username ?? null,
            ipAddress: request.ip ?? null
        });

        return {
            key: toSummary(saved, issuedAt, this.labelFor(saved, await this.targetLabels())),
            /** La seule occurrence de la valeur en clair. Elle ne réapparaîtra jamais. */
            secret: fullKey
        };
    }

    @Delete(':id')
    @HttpCode(204)
    async remove(@Param('id') id: string, @Req() request: AuthenticatedRequest): Promise<void> {
        const key = await this.manager.findOneBy(ApiKey, { id });
        if (!key) throw new NotFoundException('Clé introuvable.');

        // Révoquer supprime la ligne : une clé « désactivée » qu'un scan pourrait
        // réactiver par mégarde serait pire qu'absente. La piste d'audit garde la trace.
        await this.manager.delete(ApiKey, { id });
        await this.audit.record(this.manager, {
            operationType: 'SETTING_UPDATED',
            resourceId: id,
            description: `Clé d'API révoquée : ${key.name}`,
            userId: request.user?.username ?? null,
            ipAddress: request.ip ?? null
        });
    }

    /** Les cibles auxquelles une clé peut être restreinte, pour que l'écran propose des
     *  noms plutôt que des identifiants. */
    @Get('targets')
    async targets() {
        const [repositories, containers] = await Promise.all([
            this.manager.find(GitRepository, { order: { url: 'ASC' } }),
            this.manager.find(Container, { order: { imageName: 'ASC' } })
        ]);
        return {
            repositories: repositories.map((row) => ({ id: row.id, label: row.name || row.url })),
            containers: containers.map((row) => ({ id: row.id, label: `${row.imageName}:${row.tag}` }))
        };
    }

    private async assertTargetExists(kind: string, id: number): Promise<void> {
        const exists =
            kind === 'repository'
                ? await this.manager.countBy(GitRepository, { id })
                : await this.manager.countBy(Container, { id });
        if (!exists) {
            // Une clé restreinte à une cible inexistante ne peut rien faire, et le
            // découvrir se ferait au premier appel de la chaîne d'intégration.
            throw new BadRequestException(`Aucune cible « ${kind} » d'identifiant ${id}.`);
        }
    }

    private async targetLabels(): Promise<{ repositories: Map<number, string>; containers: Map<number, string> }> {
        const { repositories, containers } = await this.targets();
        return {
            repositories: new Map(repositories.map((row) => [row.id, row.label])),
            containers: new Map(containers.map((row) => [row.id, row.label]))
        };
    }

    private labelFor(key: ApiKey, labels: { repositories: Map<number, string>; containers: Map<number, string> }): string | null {
        if (key.targetKind === null || key.targetId === null) return null;
        const found = key.targetKind === 'repository' ? labels.repositories.get(key.targetId) : labels.containers.get(key.targetId);
        // Une cible supprimée depuis l'émission : le dire plutôt que d'afficher un vide.
        return found ?? `${key.targetKind} ${key.targetId} (supprimée)`;
    }
}

function addDays(from: Date, days: number): Date {
    const date = new Date(from);
    date.setUTCDate(date.getUTCDate() + days);
    return date;
}
