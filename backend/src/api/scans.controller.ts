import { Controller, Get, NotFoundException, Param, ParseIntPipe, Query } from '@nestjs/common';
import { InjectEntityManager } from '@nestjs/typeorm';
import { EntityManager } from 'typeorm';
import { containerDisplayName, repositoryDisplayName } from '../domain/targets/display-name';
import { Container, Finding, Repository as GitRepository, Scan } from '../persistence/entities';

const MAX_FINDINGS = 500;

/**
 * L'historique des scans, et le détail de chacun.
 *
 * **Le détail montre les constats du scan, pas le backlog de la cible.** Les deux
 * diffèrent : le backlog porte l'histoire — un problème vu il y a trois scans et toujours
 * ouvert en fait partie — tandis qu'un scan ne rend compte que de ce qu'il a observé ce
 * jour-là. Confondre les deux ferait croire qu'un scan a « trouvé » un problème qu'il n'a
 * fait que revoir.
 */
@Controller('api/v1/scans')
export class ScansController {
    constructor(@InjectEntityManager() private readonly manager: EntityManager) {}

    /** L'historique, le plus récent d'abord. */
    @Get()
    async list(@Query('repo_id') repoId?: string, @Query('container_id') containerId?: string, @Query('limit') limit?: string) {
        const where: Record<string, number> = {};
        if (repoId) where.repoId = Number(repoId);
        if (containerId) where.containerId = Number(containerId);

        const scans = await this.manager.find(Scan, {
            where: Object.keys(where).length ? where : {},
            order: { createdAt: 'DESC', id: 'DESC' },
            take: Math.min(Number(limit) || 50, 200)
        });
        const names = await this.targetNames();
        return scans.map((scan) => this.toSummary(scan, names));
    }

    @Get(':id')
    async detail(@Param('id', ParseIntPipe) id: number) {
        const scan = await this.manager.findOneBy(Scan, { id });
        if (!scan) throw new NotFoundException('Scan introuvable.');

        const findings = await this.manager.find(Finding, {
            where: { scanId: id },
            order: { severity: 'ASC', id: 'ASC' },
            take: MAX_FINDINGS
        });
        const total = await this.manager.countBy(Finding, { scanId: id });
        const names = await this.targetNames();

        return {
            ...this.toSummary(scan, names),
            subPath: scan.subPath,
            // Le SBOM n'est pas rendu ici : il pèse plusieurs mégaoctets et l'écran n'en
            // affiche rien. Son export a sa propre route.
            hasSbom: scan.sbom !== null,
            findings: findings.map((finding) => ({
                id: finding.id,
                type: finding.type,
                severity: finding.severity,
                identifier: finding.identifier,
                packageName: finding.packageName,
                packageVersion: finding.packageVersion,
                fixVersions: finding.fixVersions,
                filePath: finding.filePath,
                line: finding.line,
                description: finding.description,
                link: finding.link
            })),
            findingsTotal: total,
            // Dit explicitement quand la liste est tronquée : sans cela, un scan à mille
            // constats en montrerait cinq cents sans que rien ne l'indique.
            findingsTruncated: total > findings.length
        };
    }

    private toSummary(scan: Scan, names: { repositories: Map<number, string>; containers: Map<number, string> }) {
        return {
            id: scan.id,
            status: scan.status,
            branch: scan.branch,
            createdAt: scan.createdAt,
            durationMs: scan.durationMs,
            findingsCount: scan.findingsCount,
            newIssuesCount: scan.newIssuesCount,
            resolvedIssuesCount: scan.resolvedIssuesCount,
            error: scan.error,
            claimedBy: scan.claimedBy,
            attempts: scan.attempts,
            targetKind: scan.repoId !== null ? 'repository' : 'container',
            targetId: scan.repoId ?? scan.containerId,
            // Une cible supprimée depuis le scan : le dire plutôt que d'afficher un vide,
            // parce que l'historique du scan reste utile après la disparition de la cible.
            targetName:
                (scan.repoId !== null ? names.repositories.get(scan.repoId) : names.containers.get(scan.containerId!)) ?? 'cible supprimée'
        };
    }

    private async targetNames() {
        const [repositories, containers] = await Promise.all([this.manager.find(GitRepository), this.manager.find(Container)]);
        return {
            repositories: new Map(repositories.map((row) => [row.id, repositoryDisplayName(row)])),
            containers: new Map(containers.map((row) => [row.id, containerDisplayName(row)]))
        };
    }
}
