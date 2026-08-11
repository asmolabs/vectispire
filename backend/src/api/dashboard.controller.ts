import { Controller, Get } from '@nestjs/common';
import { InjectEntityManager } from '@nestjs/typeorm';
import { EntityManager } from 'typeorm';
import { buildOverview } from '../domain/gate/security-overview';
import { TYPE_QUALITY } from '../domain/issues/types';
import { asTimestampText } from '../domain/common/timestamp';
import { Scan, STATE_OPEN } from '../persistence/entities';
import { IssueRepository } from '../repositories/issue.repository';
import { TargetRepository } from '../repositories/target.repository';
import { toLatest, toStoredPolicy } from './gate.controller';
import type { GateIssue } from '../domain/gate/policy-gate';
import { containerDisplayName, repositoryDisplayName } from '../domain/targets/display-name';

const RECENT_SCANS = 8;

/**
 * Le tableau de bord.
 *
 * **Il ne calcule aucun agrégat qui lui soit propre.** La posture vient de
 * `buildOverview`, exactement celle qu'affiche l'écran Sécurité et qu'évalue
 * `POST /gate` ; le backlog vient du dépôt de problèmes. Un tableau de bord qui
 * réimplémente ses chiffres finit par en afficher d'autres que les écrans de détail,
 * et c'est celui qu'on croit — il est en page d'accueil.
 */
@Controller('api/v1/dashboard')
export class DashboardController {
    constructor(
        @InjectEntityManager() private readonly manager: EntityManager,
        private readonly targets: TargetRepository = new TargetRepository(),
        private readonly issues: IssueRepository = new IssueRepository()
    ) {}

    @Get()
    async overview() {
        const [repositories, containers, policies, openForGate, scansByRepository, scansByContainer, bySeverity, qualityTotal, recentScans] =
            await Promise.all([
                this.targets.findRepositories(this.manager),
                this.targets.findContainers(this.manager),
                this.targets.findActivePolicies(this.manager),
                this.targets.findOpenForGate(this.manager),
                this.targets.findLatestScans(this.manager, 'repo_id'),
                this.targets.findLatestScans(this.manager, 'container_id'),
                this.issues.countOpenBySeverity(this.manager),
                this.issues.countFiltered(this.manager, { state: STATE_OPEN, type: TYPE_QUALITY }),
                this.recentScans()
            ]);

        const posture = buildOverview({
            repositories: repositories.map((repository) => ({ id: repository.id, name: repositoryDisplayName(repository) })),
            containers: containers.map((container) => ({ id: container.id, name: containerDisplayName(container) })),
            policies: policies.map((row) => ({ targetKind: row.targetKind, targetId: row.targetId, policy: toStoredPolicy(row) })),
            openIssues: openForGate as unknown as (GateIssue & { repoId: number | null; containerId: number | null })[],
            latestScanByRepository: toLatest(scansByRepository),
            latestScanByContainer: toLatest(scansByContainer)
        });

        return {
            posture: {
                failingCount: posture.failingCount,
                totalCount: posture.totalCount,
                kevCount: posture.kevCount,
                // Une cible jamais scannée passe toutes les politiques : son absence de
                // constats n'est pas une absence de problèmes. Chiffre à part, donc.
                neverScannedCount: posture.neverScannedCount,
                lastScanFailedCount: posture.lastScanFailedCount
            },
            backlogBySeverity: bySeverity,
            /** À part, et jamais mêlé au backlog de sécurité : il ne bloque rien. */
            qualityTotal,
            /** Les cibles en échec, pour qu'il y ait quelque chose à faire depuis ici. */
            failing: posture.targets
                .filter((target) => !target.passed)
                .map((target) => ({
                    kind: target.kind,
                    targetId: target.targetId,
                    name: target.name,
                    observed: target.observed,
                    violations: target.verdict.violations
                })),
            recentScans
        };
    }

    private async recentScans() {
        const scans = await this.manager.find(Scan, { order: { createdAt: 'DESC' }, take: RECENT_SCANS });
        return scans.map((scan) => ({
            id: scan.id,
            repoId: scan.repoId,
            containerId: scan.containerId,
            status: scan.status,
            findingsCount: scan.findingsCount,
            error: scan.error,
            // TypeORM réhydrate les colonnes date : sans cela, l'écran reçoit un `Date`
            // sérialisé dans le fuseau de la machine, décalé de deux heures l'été.
            createdAt: asTimestampText(scan.createdAt)
        }));
    }
}
