import { Injectable, Logger } from '@nestjs/common';
import { InjectEntityManager } from '@nestjs/typeorm';
import { EntityManager } from 'typeorm';
import { type GateIssue, evaluate } from '../domain/gate/policy-gate';
import { describeSource, resolvePolicy } from '../domain/gate/policy-resolution';
import { containerDisplayName, repositoryDisplayName } from '../domain/targets/display-name';
import { MAX_TICKETS_PER_SWEEP, type TicketableIssue } from '../domain/tickets/ticket';
import { Container, Repository as GitRepository, Issue, STATE_OPEN, TRIAGE_FIXED, TRIAGE_NOT_AFFECTED } from '../persistence/entities';
import { SEVERITY_RANK } from '../repositories/issue.repository';
import { indexPolicies } from '../repositories/policy-index';
import { TargetRepository } from '../repositories/target.repository';
import { AuditLogService } from './audit-log.service';
import { TicketService } from './ticket.service';

/**
 * Le balayage qui ouvre les tickets.
 *
 * **Un balayage, pas un évènement.** Les notifications partent après un scan ; les tickets
 * non. Un parcours de « problèmes actionnables sans ticket » est idempotent par
 * construction — la référence stockée sur le problème *est* la clé de déduplication —
 * donc un gestionnaire en maintenance est retenté au tour suivant au lieu de perdre le
 * ticket en silence. C'est aussi pourquoi aucune outbox n'est nécessaire ici : l'état à
 * réconcilier est déjà dans la ligne du problème.
 *
 * **Le gate est évalué problème par problème, délibérément.** Évaluer tout le backlog
 * d'une cible et ouvrir un ticket pour chaque violation serait la même requête, mais le
 * ticket d'un problème dépendrait alors de quels *autres* problèmes se trouvent ouverts —
 * et « pourquoi celui-ci a un ticket et pas celui-là » doit avoir une réponse qui parle du
 * problème lui-même.
 */
@Injectable()
export class TicketSweepService {
    private readonly logger = new Logger(TicketSweepService.name);

    constructor(
        @InjectEntityManager() private readonly manager: EntityManager,
        private readonly tickets: TicketService,
        private readonly audit: AuditLogService,
        private readonly targets: TargetRepository = new TargetRepository()
    ) {}

    /** Un passage. Rend combien de tickets ont été ouverts. */
    async sweep(limit = MAX_TICKETS_PER_SWEEP): Promise<number> {
        if (!(await this.tickets.isEnabled())) return 0;

        const candidates = await this.actionableWithoutTicket(limit);
        if (candidates.length === 0) return 0;

        const policies = await this.targets.findActivePolicies(this.manager);
        const byScope = indexPolicies(policies);
        const names = await this.targetNames();

        let created = 0;
        for (const issue of candidates) {
            // Un problème appartient toujours à une cible en pratique, mais une ligne sans
            // cible doit retomber sur la politique globale plutôt que de résoudre une
            // portée `container:null` — qui lèverait et emporterait tout le balayage.
            const scope = issue.repoId ? `repository:${issue.repoId}` : issue.containerId ? `container:${issue.containerId}` : null;
            const resolved = resolvePolicy({
                forTarget: scope ? (byScope.get(scope) ?? null) : null,
                global: byScope.get('global:0') ?? null
            });

            if (evaluate([issue as unknown as GateIssue], resolved.policy).passed) {
                // Sous la barre pour cette cible : pas de ticket, et **pas de marqueur non
                // plus** — la politique peut être durcie demain, et le problème doit
                // redevenir candidat à ce moment-là.
                continue;
            }

            const ticket = await this.tickets.createForIssue(issue as unknown as TicketableIssue, this.nameOf(issue, names));
            // Laissé sans référence à dessein : le tour suivant le retentera.
            if (!ticket) continue;

            await this.manager.update(Issue, { id: issue.id }, { ticketRef: ticket.reference, ticketUrl: ticket.url });
            created += 1;

            await this.audit.record(this.manager, {
                operationType: 'TICKET_CREATED',
                resourceId: String(issue.id),
                description: `Ticket ${ticket.reference} ouvert pour ${issue.identifier || issue.type} (${describeSource(resolved)})`,
                userId: null,
                ipAddress: null
            });
        }

        if (created > 0) this.logger.log(`${created} ticket(s) ouvert(s).`);
        return created;
    }

    /**
     * Les problèmes ouverts, non triés comme écartés, et sans ticket.
     *
     * `not_affected` et `fixed` sont exclus : ce sont les deux jugements qui disent « rien
     * à planifier ». Tout le reste — y compris `under_review`, qui est le défaut — reste
     * candidat, parce qu'un problème que personne n'a encore regardé est précisément celui
     * qu'il faut faire exister ailleurs que dans un tableau de bord.
     */
    private async actionableWithoutTicket(limit: number): Promise<Issue[]> {
        return this.manager
            .createQueryBuilder(Issue, 'issue')
            .where('issue.state = :state', { state: STATE_OPEN })
            .andWhere('issue.ticket_ref IS NULL')
            .andWhere('issue.triage_status NOT IN (:...excluded)', { excluded: [TRIAGE_NOT_AFFECTED, TRIAGE_FIXED] })
            // **Le plus grave d'abord**, et non le plus ancien : le plafond par passage
            // doit servir ce qui compte le plus. Un backlog mature trié par identifiant
            // consommerait les vingt tickets sur des constats anodins insérés il y a un an,
            // et le critique d'hier attendrait des jours son tour.
            .orderBy(SEVERITY_RANK, 'ASC')
            .addOrderBy('issue.id', 'ASC')
            .take(limit)
            .getMany();
    }

    private nameOf(issue: Issue, names: { repositories: Map<number, string>; containers: Map<number, string> }): string {
        if (issue.repoId !== null) return names.repositories.get(issue.repoId) ?? `dépôt ${issue.repoId}`;
        if (issue.containerId !== null) return names.containers.get(issue.containerId) ?? `conteneur ${issue.containerId}`;
        return 'cible inconnue';
    }

    private async targetNames() {
        const [repositories, containers] = await Promise.all([this.manager.find(GitRepository), this.manager.find(Container)]);
        return {
            repositories: new Map(repositories.map((row) => [row.id, repositoryDisplayName(row)])),
            containers: new Map(containers.map((row) => [row.id, containerDisplayName(row)]))
        };
    }
}
