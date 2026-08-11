import { Controller, Get, Query } from '@nestjs/common';
import { InjectEntityManager } from '@nestjs/typeorm';
import { EntityManager } from 'typeorm';
import { verifyChain } from '../domain/audit/audit-hash';
import { AuditLogRepository } from '../repositories/audit-log.repository';
import { AdminOnly } from './auth.guard';

const DEFAULT_PAGE_SIZE = 50;
const MAX_PAGE_SIZE = 200;

@AdminOnly()
@Controller('api/v1/audit-log')
export class AuditLogController {
    constructor(
        @InjectEntityManager() private readonly manager: EntityManager,
        private readonly repository: AuditLogRepository = new AuditLogRepository()
    ) {}

    /** `limit`/`offset` comme `/issues` : une seule convention de pagination dans l'API
     *  vaut mieux qu'une commodité locale, et le type `Page<T>` du client s'y appuie. */
    @Get()
    async list(
        @Query('operation_type') operationType?: string,
        @Query('user_id') userId?: string,
        @Query('search') search?: string,
        @Query('limit') rawLimit?: string,
        @Query('offset') rawOffset?: string
    ) {
        const limit = clamp(Number(rawLimit) || DEFAULT_PAGE_SIZE, 1, MAX_PAGE_SIZE);
        const offset = Math.max(0, Number(rawOffset) || 0);
        const { rows, total } = await this.repository.findFiltered(this.manager, { operationType, userId, search }, limit, offset);
        return { items: rows, total, limit, offset };
    }

    /** Les valeurs réellement présentes, pour que le filtre ne propose rien de vide. */
    @Get('operation-types')
    async operationTypes(): Promise<string[]> {
        return this.repository.distinctOperationTypes(this.manager);
    }

    /**
     * Vérifie la chaîne d'intégrité, et **le dit à l'écran**.
     *
     * Le chaînage existe depuis le début et n'était vérifiable que par un script. Un
     * journal d'audit dont personne ne regarde jamais l'intégrité protège surtout la
     * conscience de celui qui l'a écrit : la vérification n'a de valeur que si son
     * résultat est visible sans effort.
     *
     * La lecture suit les maillons plutôt qu'un tri — deux entrées de même horodatage
     * seraient sinon départagées par un UUID, donc dans un ordre arbitraire, et une
     * chaîne intacte se déclarerait rompue.
     */
    @Get('verify')
    async verify() {
        const entries = await this.repository.findAllOldestFirst(this.manager);
        const { broken, unverifiable } = verifyChain(entries);
        return {
            total: entries.length,
            /** Antérieures au chaînage : ni une preuve ni une alerte, juste un fait. */
            unverifiable,
            verified: entries.length - unverifiable,
            intact: broken === null,
            broken
        };
    }
}

function clamp(value: number, minimum: number, maximum: number): number {
    return Math.min(Math.max(value, minimum), maximum);
}
