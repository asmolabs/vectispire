import { BadRequestException, Body, Controller, Delete, Get, HttpCode, NotFoundException, Param, ParseIntPipe, Post, Req } from '@nestjs/common';
import { InjectEntityManager } from '@nestjs/typeorm';
import { EntityManager } from 'typeorm';
import { formatImageReference, validateImageReference } from '../domain/targets/image-reference';
import { Container, Issue, STATE_OPEN } from '../persistence/entities';
import { TargetRepository } from '../repositories/target.repository';
import { AuditLogService } from '../services/audit-log.service';
import { AdminOnly } from './auth.guard';
import type { AuthenticatedRequest } from './auth.guard';

/**
 * Les images de conteneur surveillées. Même forme que `repositories.controller.ts`, et
 * même absence délibérée : pas de déclenchement de scan tant que la file n'est pas
 * portée.
 */
@Controller('api/v1/containers')
export class ContainersController {
    constructor(
        @InjectEntityManager() private readonly manager: EntityManager,
        private readonly targets: TargetRepository = new TargetRepository(),
        private readonly audit: AuditLogService = new AuditLogService()
    ) {}

    @Get()
    async list() {
        const [containers, latestScans, issues] = await Promise.all([
            this.targets.findContainers(this.manager),
            this.targets.findLatestScans(this.manager, 'container_id'),
            this.openCountByContainer()
        ]);

        return containers.map((container) => {
            const scan = latestScans.get(container.id) as unknown as Record<string, unknown> | undefined;
            return {
                ...container,
                // Calculée côté serveur : c'est la forme que le scanner emploie, et deux
                // implémentations de la même concaténation divergeraient sur les condensés.
                reference: formatImageReference(container),
                lastScan: scan ? { id: scan.id, status: scan.status, createdAt: scan.created_at ?? null, error: scan.error ?? null } : null,
                openIssues: issues.get(container.id) ?? 0
            };
        });
    }

    @AdminOnly()
    @Post()
    async create(@Body() body: Record<string, unknown>, @Req() request: AuthenticatedRequest) {
        const reference = {
            registry: asOptional(body.registry),
            imageName: String(body.image_name ?? '').trim(),
            tag: String(body.tag ?? '').trim() || 'latest'
        };
        const invalid = validateImageReference(reference);
        if (invalid) throw new BadRequestException(invalid);

        const saved = await this.manager.save(
            Container,
            Object.assign(new Container(), {
                ...reference,
                scanIntervalMinutes: body.scan_interval_minutes == null ? null : Number(body.scan_interval_minutes),
                scanCron: asOptional(body.scan_cron),
                lastScheduledScanAt: null
            })
        );
        await this.audit.record(this.manager, {
            operationType: 'SETTING_UPDATED',
            resourceId: String(saved.id),
            description: `Conteneur ajouté : ${formatImageReference(saved)}`,
            userId: request.user?.username ?? null,
            ipAddress: request.ip ?? null
        });
        return { ...saved, reference: formatImageReference(saved) };
    }

    @AdminOnly()
    @Delete(':id')
    @HttpCode(204)
    async remove(@Param('id', ParseIntPipe) id: number, @Req() request: AuthenticatedRequest): Promise<void> {
        const container = await this.manager.findOneBy(Container, { id });
        if (!container) throw new NotFoundException('Conteneur introuvable.');

        await this.manager.delete(Container, { id });
        await this.audit.record(this.manager, {
            operationType: 'SETTING_UPDATED',
            resourceId: String(id),
            description: `Conteneur supprimé : ${formatImageReference(container)}`,
            userId: request.user?.username ?? null,
            ipAddress: request.ip ?? null
        });
    }

    private async openCountByContainer(): Promise<Map<number, number>> {
        const rows: { containerId: string; count: string }[] = await this.manager
            .createQueryBuilder(Issue, 'issue')
            .select('issue.container_id', 'containerId')
            .addSelect('COUNT(*)', 'count')
            .where('issue.state = :state', { state: STATE_OPEN })
            .andWhere('issue.container_id IS NOT NULL')
            .groupBy('issue.container_id')
            .getRawMany();
        return new Map(rows.map((row) => [Number(row.containerId), Number(row.count)]));
    }
}

function asOptional(value: unknown): string | null {
    const text = typeof value === 'string' ? value.trim() : '';
    return text || null;
}
