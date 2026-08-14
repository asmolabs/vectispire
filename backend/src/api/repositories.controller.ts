import { InvalidCronExpression, validateExpression } from '../domain/scheduling/due';
import { BadRequestException, Body, Controller, Delete, Get, HttpCode, NotFoundException, Param, ParseIntPipe, Post, Req } from '@nestjs/common';
import { now } from '../domain/common/timestamp';
import { InjectEntityManager } from '@nestjs/typeorm';
import { ApiTags } from '@nestjs/swagger';
import { EntityManager } from 'typeorm';
import { validateRepositoryUrl } from '../domain/targets/git-url';
import { Repository as GitRepository, Issue, Scan, STATE_OPEN, STATUS_QUEUED } from '../persistence/entities';
import { TargetRepository } from '../repositories/target.repository';
import { AuditLogService } from '../services/audit-log.service';
import { AdminOnly } from './auth.guard';
import type { AuthenticatedRequest } from './auth.guard';
import { repositoryDisplayName } from '../domain/targets/display-name';

/** Les dépôts surveillés, et le déclenchement de leurs scans. */
@ApiTags('Cibles')
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
            // Validée ici, au point de saisie : découvrir qu'une expression a été rejetée
            // en regardant des scans *ne pas* se produire est la manière chère.
            scanCron: cronOrThrow(body.scan_cron),
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

    /**
     * Met un scan en file pour ce dépôt.
     *
     * **Mettre en file, et non lancer.** L'appel rend la main immédiatement ; c'est un
     * travailleur — intégré ou agent distant — qui réclamera la ligne. Exécuter ici
     * ferait attendre l'appelant plusieurs minutes derrière une requête HTTP, et un
     * rechargement de page relancerait le scan.
     *
     * Réservé aux administrateurs : un scan consomme du temps machine et du réseau, et
     * la file est partagée.
     */
    @AdminOnly()
    @Post(':id/scan')
    async triggerScan(@Param('id', ParseIntPipe) id: number, @Req() request: AuthenticatedRequest) {
        const repository = await this.manager.findOneBy(GitRepository, { id });
        if (!repository) throw new NotFoundException('Dépôt introuvable.');

        const pending = await this.manager.countBy(Scan, { repoId: id, status: STATUS_QUEUED });
        if (pending > 0) {
            // Refusé plutôt qu'empilé : dix clics sur le bouton donneraient dix scans
            // identiques à la suite, dont neuf sans objet.
            throw new BadRequestException('Un scan de ce dépôt est déjà en file.');
        }

        const scan = await this.manager.save(
            Scan,
            Object.assign(new Scan(), {
                repoId: repository.id,
                branch: repository.branch,
                subPath: repository.subPath,
                status: STATUS_QUEUED,
                createdAt: now()
            })
        );

        await this.audit.record(this.manager, {
            operationType: 'SCAN_TRIGGERED',
            resourceId: String(scan.id),
            description: `Scan demandé : ${repository.url}`,
            userId: request.user?.username ?? null,
            ipAddress: request.ip ?? null
        });
        return { id: scan.id, status: scan.status };
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

/**
 * Une expression cron valide, `null`, ou un 400 que l'opérateur peut lire.
 *
 * Un 400 et non un 500 : l'expression vient de l'utilisateur, et le message porte le
 * format attendu avec deux exemples.
 */
function cronOrThrow(value: unknown): string | null {
    try {
        return validateExpression(typeof value === 'string' ? value : null);
    } catch (error) {
        if (error instanceof InvalidCronExpression) throw new BadRequestException(error.message);
        throw error;
    }
}

function asOptional(value: unknown): string | null {
    const text = typeof value === 'string' ? value.trim() : '';
    return text || null;
}
