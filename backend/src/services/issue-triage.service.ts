import { EntityManager } from 'typeorm';
import { now } from '../domain/common/timestamp';
import { InvalidTriageError, TriageRequest, decideTriage, expireTriage, isTriageExpired } from '../domain/issues/triage';
import { Issue } from '../persistence/entities';
import { IssueRepository } from '../repositories/issue.repository';

/**
 * L'enregistrement d'une décision humaine sur un problème.
 *
 * Le service applique ; les règles vivent dans `domain/issues/triage.ts`. La séparation
 * n'est pas décorative : ce sont ces règles-là qu'un document VEX exporte, et elles
 * doivent se tester sans base.
 */
export class IssueTriageService {
    constructor(private readonly issues: IssueRepository = new IssueRepository()) {}

    /**
     * Lève `InvalidTriageError` sur tout ce qui est invalide, avec un message destiné à
     * être montré tel quel : c'est la personne qui triait qui doit savoir pourquoi sa
     * décision est refusée.
     */
    async triage(manager: EntityManager, issueId: number, request: TriageRequest): Promise<Issue> {
        // Validé **avant** de charger le problème : une demande mal formée ne doit pas
        // coûter une requête, et le message ne dépend pas de l'existence de la cible.
        const decision = decideTriage(request, now());

        const issue = await this.issues.findById(manager, issueId);
        if (!issue) throw new InvalidTriageError('Problème introuvable.');

        issue.triageStatus = decision.status;
        issue.triageJustification = decision.justification;
        issue.triageComment = decision.comment;
        issue.triagedBy = decision.triagedBy;
        issue.triagedAt = decision.triagedAt;
        issue.triageExpiresAt = decision.expiresAt;

        const [saved] = await this.issues.save(manager, [issue]);
        return saved;
    }

    /**
     * Ramène sous revue les décisions arrivées à échéance.
     *
     * Appelée au tick de l'ordonnanceur et non au chargement d'une page : une
     * suppression qui expire pendant la nuit doit cesser de supprimer dans le document
     * VEX qu'un client télécharge et dans le verdict qu'un pipeline demande à trois
     * heures du matin — pas seulement quand quelqu'un ouvre l'écran.
     */
    async expireStale(manager: EntityManager): Promise<Issue[]> {
        const moment = now();
        const candidates = await manager
            .createQueryBuilder(Issue, 'issue')
            .where('issue.triage_expires_at IS NOT NULL')
            .andWhere('issue.triage_expires_at <= :moment', { moment })
            .getMany();

        // Normalisé avant d'atteindre la règle : ce que rend une entité TypeORM est un
        // `Date`, et la règle compare des chaînes (voir `asTimestampText`).
        const expired = candidates.filter((issue) =>
            isTriageExpired({ triageStatus: issue.triageStatus, triageExpiresAt: issue.triageExpiresAt }, moment)
        );
        for (const issue of expired) expireTriage(issue);
        await this.issues.save(manager, expired);
        return expired;
    }
}
