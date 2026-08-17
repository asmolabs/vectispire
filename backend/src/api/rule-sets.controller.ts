import { BadRequestException, Body, Controller, Get, NotFoundException, Param, ParseIntPipe, Post, Req } from '@nestjs/common';
import { InjectEntityManager } from '@nestjs/typeorm';
import { ApiTags } from '@nestjs/swagger';
import { EntityManager } from 'typeorm';
import { InvalidRuleSetError, type UploadedRuleFile } from '../domain/rules/rule-set';
import { AuditOperation } from '../persistence/entities';
import { AuditLogService } from '../services/audit-log.service';
import { RuleSetService } from '../services/rule-set.service';
import { AdminOnly } from './auth.guard';
import type { AuthenticatedRequest } from './auth.guard';

/**
 * Uploading Semgrep rule sets, and choosing which one is active.
 *
 * Zanshin bundles one rule — the public sets are not redistributable — so an operator's
 * coverage arrives from outside. The other route, `ZANSHIN_SEMGREP_RULES_DIR`, is read by
 * the process that scans, so every remote agent needs it provisioned on its own filesystem
 * and the control plane cannot check that it was. These routes remove that asymmetry.
 *
 * **Administrators only, and audited.** Changing the rule set changes what the scanner
 * looks for, which is the same class of decision as changing a gate policy.
 *
 * **Upload and activation are two calls, deliberately.** Activation is the destructive
 * one: a rule that is not in the new set stops being found, and the next scan resolves its
 * open issues along with their triage decisions. The `impact` route exists so that the
 * screen can say how many, by name, before anybody clicks — and the number it showed is
 * recorded on the activation.
 */
@ApiTags('Administration')
@Controller('api/v1/rule-sets')
export class RuleSetsController {
    constructor(
        @InjectEntityManager() private readonly manager: EntityManager,
        private readonly ruleSets: RuleSetService,
        private readonly audit: AuditLogService
    ) {}

    /** Every stored set, without its files. */
    @Get()
    @AdminOnly()
    async list() {
        return { ruleSets: await this.ruleSets.list() };
    }

    /**
     * Stores an upload. Does not activate it.
     *
     * The files arrive as JSON rather than multipart, which is not only simpler: it means
     * there is no archive to extract server-side, and therefore no path traversal to guard
     * against. The names are recorded and never used as paths — see `domain/rules/rule-set`.
     */
    @Post()
    @AdminOnly()
    async upload(@Req() request: AuthenticatedRequest, @Body() body: { name?: string; files?: UploadedRuleFile[] }) {
        const files = Array.isArray(body?.files) ? body.files : [];

        try {
            const stored = await this.ruleSets.store(files, body?.name ?? '', request.user?.username ?? null);

            await this.audit.record(this.manager, {
                operationType: AuditOperation.RULE_SET_UPLOADED,
                resourceId: String(stored.id),
                description: `Rule set "${stored.name}" uploaded: ${stored.fileCount} files, ${stored.ruleCount} rules.`,
                userId: request.user?.username ?? null,
                ipAddress: request.ip ?? null
            });

            return { id: stored.id, contentHash: stored.contentHash, ruleCount: stored.ruleCount, fileCount: stored.fileCount };
        } catch (error) {
            // Refusals here are the operator's to read and act on — a file that is not YAML,
            // an upload over the cap — so they come back as 400 rather than 500.
            if (error instanceof InvalidRuleSetError) throw new BadRequestException(error.message);
            throw error;
        }
    }

    /**
     * What activating this set would cost.
     *
     * **The screen must show this before offering the button.** A rule id enters an issue's
     * fingerprint, so the rules that disappear take their open issues with them: the triage
     * decisions, the justifications, the review dates. Nothing errors, and the dashboard
     * looks better afterwards — which is precisely why it has to be said out loud.
     */
    @Get(':id/impact')
    @AdminOnly()
    async impact(@Param('id', ParseIntPipe) id: number) {
        const candidate = await this.ruleSets.byId(id);
        if (!candidate) throw new NotFoundException(`No rule set with id ${id}.`);

        return this.ruleSets.impactOf(candidate);
    }

    /**
     * Activates a set.
     *
     * `note` is what the operator was shown when they confirmed. Recording it is what makes
     * "why did four hundred issues close that afternoon" answerable six months later.
     */
    @Post(':id/activate')
    @AdminOnly()
    async activate(@Req() request: AuthenticatedRequest, @Param('id', ParseIntPipe) id: number, @Body() body: { note?: string }) {
        try {
            const activated = await this.ruleSets.activate(id, body?.note?.trim() || null);

            await this.audit.record(this.manager, {
                operationType: AuditOperation.RULE_SET_ACTIVATED,
                resourceId: String(activated.id),
                description: `Rule set "${activated.name}" activated. ${activated.activationNote ?? 'No impact recorded.'}`,
                userId: request.user?.username ?? null,
                ipAddress: request.ip ?? null
            });

            return { id: activated.id, contentHash: activated.contentHash };
        } catch (error) {
            if (error instanceof InvalidRuleSetError) throw new NotFoundException(error.message);
            throw error;
        }
    }

    /** Returns to the bundled rules alone. Audited like an activation: it changes coverage. */
    @Post('deactivate')
    @AdminOnly()
    async deactivate(@Req() request: AuthenticatedRequest) {
        await this.ruleSets.deactivateAll();

        await this.audit.record(this.manager, {
            operationType: AuditOperation.RULE_SET_DEACTIVATED,
            resourceId: 'all',
            description: 'Uploaded rule sets deactivated; scans fall back to the bundled rules.',
            userId: request.user?.username ?? null,
            ipAddress: request.ip ?? null
        });

        return { active: null };
    }
}
