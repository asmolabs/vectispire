import { EntityManager, In } from 'typeorm';
import { Issue, STATE_OPEN } from '../persistence/entities';
import { SECURITY_TYPES } from '../domain/issues/types';

export interface IssueFilters {
    state?: string | null;
    severity?: string | null;
    type?: string | null;
    triageStatus?: string | null;
    repoId?: number | null;
    containerId?: number | null;
    onlyDirect?: boolean;
    search?: string | null;
}

/** Les seules colonnes sur lesquelles un regroupement est permis. */
const GROUPABLE = { rule: 'identifier', file: 'file_path', target: 'repo_id' } as const;
export type GroupableColumn = keyof typeof GROUPABLE;

/**
 * L'ordre de gravité, en SQL.
 *
 * Écrit ici plutôt que déduit d'un `ORDER BY severity` : l'ordre alphabétique placerait
 * « critical » après « high » et « low » avant « medium ». Il suit `SEVERITY_ORDER` du
 * domaine, et `unknown` se classe sous `low` pour la même raison qu'ailleurs — le
 * backend OSV le renvoie dès qu'un avis n'a pas de sévérité normalisée.
 */
const SEVERITY_RANK = `CASE issue.severity
    WHEN 'critical' THEN 0
    WHEN 'high' THEN 1
    WHEN 'medium' THEN 2
    WHEN 'low' THEN 3
    WHEN 'negligible' THEN 4
    ELSE 5 END`;

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

    /**
     * Le backlog filtré, paginé.
     *
     * `count` et `find` partagent la construction du `WHERE` : deux constructions
     * séparées finiraient par diverger, et le symptôme serait une pagination qui annonce
     * un nombre de pages que la liste ne contient pas.
     */
    async findFiltered(manager: EntityManager, filters: IssueFilters, page: { limit: number; offset: number }): Promise<Issue[]> {
        return this.filtered(manager, filters)
            // Les plus graves d'abord, puis les plus récemment vues : c'est l'ordre
            // dans lequel quelqu'un veut traiter un backlog.
            .orderBy(SEVERITY_RANK, 'ASC')
            .addOrderBy('issue.last_seen_at', 'DESC')
            .addOrderBy('issue.id', 'DESC')
            .limit(page.limit)
            .offset(page.offset)
            .getMany();
    }

    async countFiltered(manager: EntityManager, filters: IssueFilters): Promise<number> {
        return this.filtered(manager, filters).getCount();
    }

    async findById(manager: EntityManager, id: number): Promise<Issue | null> {
        return manager.findOneBy(Issue, { id });
    }

    private filtered(manager: EntityManager, filters: IssueFilters) {
        const query = manager.createQueryBuilder(Issue, 'issue');

        if (filters.state) query.andWhere('issue.state = :state', { state: filters.state });
        if (filters.severity) query.andWhere('issue.severity = :severity', { severity: filters.severity });
        if (filters.type) query.andWhere('issue.type = :type', { type: filters.type });
        if (filters.triageStatus) query.andWhere('issue.triage_status = :triageStatus', { triageStatus: filters.triageStatus });
        if (filters.repoId != null) query.andWhere('issue.repo_id = :repoId', { repoId: filters.repoId });
        if (filters.containerId != null) query.andWhere('issue.container_id = :containerId', { containerId: filters.containerId });
        // `true` seulement : « ne montre que les directes » est une demande, « montre
        // aussi les transitives » est le défaut. Filtrer sur `false` cacherait les
        // problèmes dont on ignore la nature (`null`), qui sont les plus nombreux sur
        // un dépôt sans graphe de dépendances.
        if (filters.onlyDirect) query.andWhere('issue.is_direct_dependency = true');
        if (filters.search) {
            query.andWhere('(issue.identifier ILIKE :search OR issue.package_name ILIKE :search OR issue.file_path ILIKE :search)', {
                search: `%${filters.search}%`
            });
        }
        return query;
    }

    /**
     * Les problèmes ouverts d'un type, groupés par une colonne, les plus nombreux d'abord.
     *
     * C'est ce qui rend l'écran Qualité utile plutôt que redondant : un backlog de
     * qualité à quatre chiffres ne se traite pas ligne à ligne, et « huit règles font
     * soixante-dix pour cent de la dette » est le seul cadrage actionnable devant lui.
     * Un filtre sur `/issues` ne dirait pas cela.
     *
     * La colonne est choisie dans une liste fermée et non interpolée depuis l'appelant :
     * un nom de colonne ne peut pas être un paramètre lié, donc la seule protection
     * contre une injection est qu'il ne vienne jamais de l'extérieur.
     */
    /**
     * Le backlog ouvert par sévérité, **hors qualité**.
     *
     * L'exclusion est le point : sans elle, le chiffre de tête du tableau de bord passe
     * à quatre chiffres le jour de la mise en service du SAST, et devient le nombre que
     * plus personne ne regarde.
     */
    async countOpenBySeverity(manager: EntityManager): Promise<Record<string, number>> {
        const rows: { severity: string | null; count: string }[] = await manager
            .createQueryBuilder(Issue, 'issue')
            .select('issue.severity', 'severity')
            .addSelect('COUNT(*)', 'count')
            .where('issue.state = :state', { state: STATE_OPEN })
            .andWhere('issue.type IN (:...types)', { types: [...SECURITY_TYPES] })
            .groupBy('issue.severity')
            .getRawMany();

        const counts: Record<string, number> = {};
        for (const row of rows) counts[row.severity ?? 'unknown'] = Number(row.count);
        return counts;
    }

    async countOpenGrouped(manager: EntityManager, type: string, column: GroupableColumn, limit = 8): Promise<{ label: string | null; count: number }[]> {
        const rows: { label: string | null; count: string }[] = await manager
            .createQueryBuilder(Issue, 'issue')
            .select(`issue.${GROUPABLE[column]}`, 'label')
            .addSelect('COUNT(*)', 'count')
            .where('issue.state = :state', { state: STATE_OPEN })
            .andWhere('issue.type = :type', { type })
            .groupBy(`issue.${GROUPABLE[column]}`)
            .orderBy('COUNT(*)', 'DESC')
            .limit(limit)
            .getRawMany();
        // `COUNT(*)` revient en chaîne : PostgreSQL le rend en `bigint`, et le pilote ne
        // suppose pas qu'un bigint tient dans un `number`.
        return rows.map((row) => ({ label: row.label, count: Number(row.count) }));
    }

    async save(manager: EntityManager, issues: Issue[]): Promise<Issue[]> {
        if (issues.length === 0) return [];
        return manager.save(Issue, issues);
    }
}
