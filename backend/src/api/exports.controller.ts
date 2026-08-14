import { BadRequestException, Controller, Get, Header, NotFoundException, Param, Query, Res } from '@nestjs/common';
import { InjectEntityManager } from '@nestjs/typeorm';
import { ApiOkResponse, ApiOperation, ApiTags } from '@nestjs/swagger';
import type { Response } from 'express';
import { EntityManager } from 'typeorm';
import { now } from '../domain/common/timestamp';
import { ExportableIssue, buildIssuesCsv, buildOpenVexDocument, buildSarifDocument } from '../domain/exports/exports';
import { TARGET_CONTAINER, TARGET_REPOSITORY } from '../domain/gate/security-overview';
import { Container, Issue, Repository as GitRepository } from '../persistence/entities';
import { IssueRepository } from '../repositories/issue.repository';

/**
 * Les trois formats que Zanshin remet à quelqu'un d'autre : une plateforme de code
 * scanning, un auditeur, un tableur.
 *
 * Les documents sont construits par le domaine, déjà vérifié octet pour octet contre
 * l'implémentation Python. Ce contrôleur ne fait que choisir les problèmes et poser les
 * en-têtes — c'est délibérément tout ce qu'il a le droit de faire.
 */
@ApiTags('Intégration continue')
@Controller('api/v1/targets/:kind/:id')
export class ExportsController {
    constructor(
        @InjectEntityManager() private readonly manager: EntityManager,
        private readonly issues: IssueRepository = new IssueRepository()
    ) {}

    @ApiOperation({
        summary: 'Le backlog au format SARIF 2.1.0',
        description:
            "Ce qui sort un constat du tableau de bord pour le poser sur la demande de fusion qui l'a introduit — " +
            'GitHub code scanning, GitLab, Azure DevOps. Les constats de qualité y portent leurs propres étiquettes : ' +
            "les marquer « security » les ferait remonter comme des alertes de sécurité."
    })
    @ApiOkResponse({ description: 'Un document SARIF, en pièce jointe.' })
    @Get('issues.sarif')
    @Header('Content-Type', 'application/sarif+json')
    async sarif(@Param('kind') kind: string, @Param('id') id: string, @Res({ passthrough: true }) response: Response) {
        const { targetId, name } = await this.target(kind, id);
        response.setHeader('Content-Disposition', `attachment; filename="zanshin-${kind}-${targetId}.sarif"`);

        return buildSarifDocument(await this.exportable(kind, targetId), {
            targetName: name,
            toolVersion: process.env.ZANSHIN_VERSION ?? '1.0.0',
            informationUri: process.env.ZANSHIN_PUBLIC_URL ?? null
        });
    }

    @ApiOperation({
        summary: 'Les décisions de triage au format OpenVEX',
        description:
            "L'auteur, l'identifiant et l'horodatage appartiennent à qui publie le document : un VEX est une assertion " +
            'sur qui a dit quoi, et quand. L\'appelant peut donc fournir l\'auteur.'
    })
    @ApiOkResponse({ description: 'Un document OpenVEX.' })
    @Get('vex')
    @Header('Content-Type', 'application/json')
    async vex(@Param('kind') kind: string, @Param('id') id: string, @Query('author') author?: string) {
        const { targetId, name } = await this.target(kind, id);

        // `author`, `documentId` et `timestamp` appartiennent à qui publie le document,
        // pas à une fonction utilitaire : un VEX est une assertion sur qui a dit quoi et
        // quand. L'appelant peut donc fournir l'auteur.
        return buildOpenVexDocument(await this.exportable(kind, targetId), {
            author: author || (process.env.ZANSHIN_VEX_AUTHOR ?? 'Zanshin'),
            productId: name,
            documentId: `${process.env.ZANSHIN_PUBLIC_URL ?? 'urn:zanshin'}/vex/${kind}/${targetId}`,
            timestamp: now()
        });
    }

    @ApiOperation({ summary: 'Le backlog en CSV' })
    @ApiOkResponse({ description: 'Un fichier CSV, en pièce jointe.' })
    @Get('issues.csv')
    @Header('Content-Type', 'text/csv; charset=utf-8')
    async csv(@Param('kind') kind: string, @Param('id') id: string, @Query('state') state: string | undefined, @Res({ passthrough: true }) response: Response) {
        const { targetId } = await this.target(kind, id);
        response.setHeader('Content-Disposition', `attachment; filename="zanshin-${kind}-${targetId}.csv"`);

        return buildIssuesCsv(await this.exportable(kind, targetId, state));
    }

    /**
     * Les problèmes d'une cible, sous la forme que le domaine attend.
     *
     * `asTimestampText` sur chaque date : ce que rend une entité TypeORM est un `Date`,
     * et les exports écrivent des horodatages en texte. Sans cette normalisation, un
     * document CSV remis à un auditeur porterait « Mon Aug 10 2026 … » au lieu d'une
     * date ISO, et décalée du fuseau de la machine par-dessus le marché.
     */
    private async exportable(kind: string, targetId: number, state?: string): Promise<ExportableIssue[]> {
        const filters = kind === TARGET_REPOSITORY ? { repoId: targetId } : { containerId: targetId };
        const rows = await this.issues.findFiltered(
            this.manager,
            { ...filters, state: state === 'all' ? null : (state ?? null) },
            // Les exports ne paginent pas : un document partiel remis à un auditeur
            // serait pire qu'un document lourd. La borne haute reste une protection
            // contre un backlog pathologique.
            { limit: 50_000, offset: 0 }
        );
        return rows.map(toExportable);
    }

    private async target(kind: string, rawId: string): Promise<{ targetId: number; name: string }> {
        const targetId = Number(rawId);
        if (!Number.isFinite(targetId)) throw new BadRequestException('Identifiant de cible invalide.');

        if (kind === TARGET_REPOSITORY) {
            const repository = await this.manager.findOneBy(GitRepository, { id: targetId });
            if (!repository) throw new NotFoundException('Dépôt introuvable.');
            return { targetId, name: repository.name || repository.url };
        }
        if (kind === TARGET_CONTAINER) {
            const container = await this.manager.findOneBy(Container, { id: targetId });
            if (!container) throw new NotFoundException('Conteneur introuvable.');
            return { targetId, name: `${container.imageName}:${container.tag}` };
        }
        throw new BadRequestException(`Type de cible inconnu : ${kind}. Attendu « repository » ou « container ».`);
    }
}

function toExportable(issue: Issue): ExportableIssue {
    return {
        ...issue,
        triagedAt: issue.triagedAt,
        triageExpiresAt: issue.triageExpiresAt,
        firstSeenAt: issue.firstSeenAt,
        lastSeenAt: issue.lastSeenAt
    } as ExportableIssue;
}
