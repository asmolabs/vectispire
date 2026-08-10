import { BadRequestException, Body, Controller, Get, NotFoundException, Param, ParseIntPipe, Post, Query, Req } from '@nestjs/common';
import { InjectEntityManager } from '@nestjs/typeorm';
import { EntityManager } from 'typeorm';
import { InvalidTriageError } from '../domain/issues/triage';
import { STATE_OPEN } from '../persistence/entities';
import { IssueFilters, IssueRepository } from '../repositories/issue.repository';
import { AuditLogService } from '../services/audit-log.service';
import { IssueTriageService } from '../services/issue-triage.service';
import type { AuthenticatedRequest } from './auth.guard';

/**
 * Le backlog et le triage.
 *
 * Deux garde-fous de pagination valent d'être énoncés :
 *
 * - **`limit` est borné à 500.** Sans plafond, un appelant demandant `limit=1000000`
 *   ferait charger tout le backlog en mémoire — pas une attaque, seulement un client
 *   qui veut « tout » et ne sait pas ce que « tout » pèse.
 * - **`total` est compté avec les mêmes filtres que la page.** Deux constructions
 *   séparées finiraient par diverger, et le symptôme serait une pagination annonçant
 *   des pages que la liste ne contient pas.
 */
export const MAX_PAGE_SIZE = 500;
const DEFAULT_PAGE_SIZE = 50;

@Controller('api/v1/issues')
export class IssuesController {
    constructor(
        @InjectEntityManager() private readonly manager: EntityManager,
        private readonly triageService: IssueTriageService,
        private readonly audit: AuditLogService,
        private readonly issues: IssueRepository = new IssueRepository()
    ) {}

    @Get()
    async list(@Query() query: Record<string, string | undefined>) {
        const limit = boundedInt(query.limit, DEFAULT_PAGE_SIZE, 1, MAX_PAGE_SIZE);
        const offset = boundedInt(query.offset, 0, 0, Number.MAX_SAFE_INTEGER);

        const filters: IssueFilters = {
            // `state` a un défaut, et les autres non : un backlog s'ouvre sur ce qui est
            // ouvert. `state=all` demande explicitement le contraire.
            state: query.state === 'all' ? null : (query.state ?? STATE_OPEN),
            severity: query.severity ?? null,
            type: query.type ?? null,
            triageStatus: query.triage_status ?? null,
            repoId: optionalInt(query.repository_id),
            containerId: optionalInt(query.container_id),
            onlyDirect: query.only_direct === 'true',
            search: query.search ?? null
        };

        const [items, total] = await Promise.all([
            this.issues.findFiltered(this.manager, filters, { limit, offset }),
            this.issues.countFiltered(this.manager, filters)
        ]);

        return { items, total, limit, offset };
    }

    @Post(':id/triage')
    async triage(@Param('id', ParseIntPipe) id: number, @Body() body: Record<string, unknown>, @Req() request: AuthenticatedRequest) {
        const actor = request.user?.username ?? 'inconnu';
        try {
            const issue = await this.triageService.triage(this.manager, id, {
                status: String(body.status ?? ''),
                actor,
                justification: asOptionalString(body.justification),
                comment: asOptionalString(body.comment),
                expiresInDays: body.expires_in_days == null ? null : Number(body.expires_in_days)
            });

            // Un triage peut supprimer un constat : c'est une décision de sécurité, et
            // elle appartient à la piste d'audit au même titre qu'un changement de rôle.
            await this.audit.record(this.manager, {
                operationType: 'ISSUE_TRIAGED',
                resourceId: String(id),
                description: `Triage « ${issue.triageStatus} »${issue.triageJustification ? ` (${issue.triageJustification})` : ''}`,
                userId: actor,
                ipAddress: request.ip ?? null
            });

            return issue;
        } catch (error) {
            if (error instanceof InvalidTriageError) {
                // Le message du domaine est rendu tel quel : il est écrit pour la
                // personne qui triait, pas pour un journal.
                if (error.message === 'Problème introuvable.') throw new NotFoundException(error.message);
                throw new BadRequestException(error.message);
            }
            throw error;
        }
    }
}

function boundedInt(raw: string | undefined, fallback: number, min: number, max: number): number {
    const parsed = Number(raw);
    if (!Number.isFinite(parsed)) return fallback;
    return Math.min(Math.max(Math.trunc(parsed), min), max);
}

function optionalInt(raw: string | undefined): number | null {
    const parsed = Number(raw);
    return Number.isFinite(parsed) ? Math.trunc(parsed) : null;
}

function asOptionalString(value: unknown): string | null {
    return typeof value === 'string' ? value : null;
}
