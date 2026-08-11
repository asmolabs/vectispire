import { BadRequestException, Body, Controller, Delete, Get, HttpCode, NotFoundException, Param, ParseIntPipe, Post, Req } from '@nestjs/common';
import { InjectEntityManager } from '@nestjs/typeorm';
import { EntityManager } from 'typeorm';
import { validateRepositoryUrl } from '../domain/targets/git-url';
import { Repository as GitRepository, Issue, STATE_OPEN } from '../persistence/entities';
import { TargetRepository } from '../repositories/target.repository';
import { AuditLogService } from '../services/audit-log.service';
import { AdminOnly } from './auth.guard';
import type { AuthenticatedRequest } from './auth.guard';
import { repositoryDisplayName } from '../domain/targets/display-name';

/**
 * Les dépôts surveillés.
 *
 * **Il n'y a pas d'endpoint pour déclencher un scan**, et c'est délibéré : la file de
 * scans n'est pas encore portée (lot 4). Offrir un bouton qui n'aboutirait pas serait
 * pire que ne rien offrir — l'écran dit donc ce qui manque plutôt que de le simuler.
 */
@Controller('api/v1/repositories')
export class RepositoriesController {
    constructor(
        @InjectEntityManager() private readonly manager: EntityManager,
        private readonly targets: TargetRepository = new TargetRepository(),
        private readonly audit: AuditLogService = new AuditLogService()
    ) {}

    /** La liste, avec le dernier scan et le nombre de problèmes à traiter de chacun. */
    @Get()
    async list() {
        const [repositories, latestScans, issues] = await Promise.all([
            this.targets.findRepositories(this.manager),
            this.targets.findLatestScans(this.manager, 'repo_id'),
            this.openCountByRepository()
        ]);

        return repositories.map((repository) => {
            const scan = latestScans.get(repository.id) as unknown as Record<string, unknown> | undefined;
            return {
                ...repository,
                displayName: repositoryDisplayName(repository),
                lastScan: scan ? { id: scan.id, status: scan.status, createdAt: scan.created_at ?? null, error: scan.error ?? null } : null,
                openIssues: issues.get(repository.id) ?? 0
            };
        });
    }

    @AdminOnly()
    @Post()
    async create(@Body() body: Record<string, unknown>, @Req() request: AuthenticatedRequest) {
        const url = String(body.url ?? '').trim();
        // Validé **ici et pas seulement au scan** : une URL non validée qui atteint un
        // `git clone` est une exécution de code arbitraire, pas une mauvaise saisie.
        const invalid = validateRepositoryUrl(url);
        if (invalid) throw new BadRequestException(invalid);

        const repository = Object.assign(new GitRepository(), {
            url,
            branch: String(body.branch ?? 'main').trim() || 'main',
            name: asOptional(body.name),
            subPath: asOptional(body.sub_path),
            scanIntervalMinutes: body.scan_interval_minutes == null ? null : Number(body.scan_interval_minutes),
            scanCron: asOptional(body.scan_cron),
            lastScheduledScanAt: null,
            sshKeyId: asOptional(body.ssh_key_id)
        });

        const saved = await this.manager.save(GitRepository, repository);
        await this.audit.record(this.manager, {
            operationType: 'SETTING_UPDATED',
            resourceId: String(saved.id),
            description: `Dépôt ajouté : ${saved.url}`,
            userId: request.user?.username ?? null,
            ipAddress: request.ip ?? null
        });
        return saved;
    }

    @AdminOnly()
    @Delete(':id')
    @HttpCode(204)
    async remove(@Param('id', ParseIntPipe) id: number, @Req() request: AuthenticatedRequest): Promise<void> {
        const repository = await this.manager.findOneBy(GitRepository, { id });
        if (!repository) throw new NotFoundException('Dépôt introuvable.');

        // Les scans, constats et problèmes suivent par cascade (migration 0014). C'est
        // voulu : garder le backlog d'une cible qui n'existe plus le ferait compter
        // indéfiniment dans les totaux sans que personne puisse le traiter.
        await this.manager.delete(GitRepository, { id });
        await this.audit.record(this.manager, {
            operationType: 'SETTING_UPDATED',
            resourceId: String(id),
            description: `Dépôt supprimé : ${repository.url}`,
            userId: request.user?.username ?? null,
            ipAddress: request.ip ?? null
        });
    }

    private async openCountByRepository(): Promise<Map<number, number>> {
        const rows: { repoId: string; count: string }[] = await this.manager
            .createQueryBuilder(Issue, 'issue')
            .select('issue.repo_id', 'repoId')
            .addSelect('COUNT(*)', 'count')
            .where('issue.state = :state', { state: STATE_OPEN })
            .andWhere('issue.repo_id IS NOT NULL')
            .groupBy('issue.repo_id')
            .getRawMany();
        return new Map(rows.map((row) => [Number(row.repoId), Number(row.count)]));
    }
}

function asOptional(value: unknown): string | null {
    const text = typeof value === 'string' ? value.trim() : '';
    return text || null;
}
