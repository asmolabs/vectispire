import { EntityManager, In } from 'typeorm';
import { Issue, STATE_OPEN } from '../persistence/entities';

/**
 * Accès aux problèmes. **Aucune règle métier ici** : la règle de couches veut qu'un
 * dépôt sache interroger et qu'un service sache décider.
 *
 * Chaque méthode reçoit son `EntityManager` plutôt que d'en injecter un. C'est la même
 * distinction que côté Python entre les services dont la session est portée par leurs
 * dépôts et ceux qui la reçoivent en paramètre : la réconciliation d'un scan tourne
 * dans **la** transaction ouverte par l'appelant, celle qui doit aussi contenir
 * l'écriture de l'outbox. Un dépôt qui ouvrirait la sienne casserait cette garantie
 * sans rien signaler.
 */
export class IssueRepository {
    /**
     * Les problèmes existants pour un lot d'empreintes, en **une** requête.
     *
     * Une requête par constat serait invisible sur un dépôt de démonstration et
     * ruineuse sur un vrai : un premier scan d'un projet mature produit des milliers
     * de constats.
     *
     * PostgreSQL a une limite au nombre de paramètres liés d'une requête (65535), donc
     * le lot est découpé. Sans ce découpage, la panne n'arrive que sur les gros dépôts
     * — c'est-à-dire précisément ceux où elle coûte le plus cher.
     */
    async findByFingerprints(manager: EntityManager, fingerprints: string[]): Promise<Map<string, Issue>> {
        const found = new Map<string, Issue>();
        if (fingerprints.length === 0) return found;

        const CHUNK = 1000;
        for (let offset = 0; offset < fingerprints.length; offset += CHUNK) {
            const slice = fingerprints.slice(offset, offset + CHUNK);
            const issues = await manager.find(Issue, { where: { fingerprint: In(slice) } });
            for (const issue of issues) found.set(issue.fingerprint, issue);
        }
        return found;
    }

    /**
     * Les problèmes ouverts d'une cible, restreints aux types donnés.
     *
     * La restriction par type n'est pas un filtre de confort : c'est elle qui empêche
     * un scan de conteneur de résoudre les constats de secrets d'un dépôt, qu'il n'a
     * pas cherchés.
     */
    async findOpenByTarget(
        manager: EntityManager,
        target: { repoId: number | null; containerId: number | null },
        types: string[]
    ): Promise<Issue[]> {
        if (types.length === 0) return [];

        const query = manager
            .createQueryBuilder(Issue, 'issue')
            .where('issue.state = :state', { state: STATE_OPEN })
            .andWhere('issue.type IN (:...types)', { types });

        // `repoId` et `containerId` sont exclusifs. Écrire les deux conditions
        // laisserait passer les problèmes de l'autre famille dont la colonne est nulle.
        if (target.repoId != null) query.andWhere('issue.repo_id = :repoId', { repoId: target.repoId });
        else query.andWhere('issue.container_id = :containerId', { containerId: target.containerId });

        return query.getMany();
    }

    async save(manager: EntityManager, issues: Issue[]): Promise<Issue[]> {
        if (issues.length === 0) return [];
        return manager.save(Issue, issues);
    }
}
