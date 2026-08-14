import { EntityManager, IsNull, Not } from 'typeorm';
import { Container, GatePolicyRow, Issue, Repository as GitRepository, STATE_OPEN, Scan } from '../persistence/entities';

/**
 * Les cibles — dépôts et conteneurs — et ce qu'il faut savoir d'elles.
 *
 * Regroupés dans un même dépôt de données parce que tout ce qui les concerne les traite
 * ensemble : la vue de posture, le tableau de bord, la liste des cibles de l'API. Les
 * séparer obligerait chaque appelant à faire deux fois le même travail et à recoller.
 */
export class TargetRepository {
    async findRepositories(manager: EntityManager): Promise<GitRepository[]> {
        return manager.find(GitRepository, { order: { id: 'ASC' } });
    }

    async findContainers(manager: EntityManager): Promise<Container[]> {
        return manager.find(Container, { order: { id: 'ASC' } });
    }

    /**
     * Le dernier scan de chaque cible, en **une** requête plutôt qu'une par cible.
     *
     * **`ROW_NUMBER()` et non `DISTINCT ON`.** Le second est propre à PostgreSQL, et
     * l'était de façon assumée tant que PostgreSQL était le seul moteur ; il ne l'est plus.
     * La fenêtre est un peu plus verbeuse et fait exactement la même chose sur les deux
     * moteurs — MySQL 8 et PostgreSQL la comprennent tous les deux.
     *
     * Le tri porte aussi sur `id` : deux scans créés dans la même milliseconde rendraient
     * sinon un gagnant indéterminé, et « le dernier scan » changerait d'un appel à l'autre.
     */
    async findLatestScans(manager: EntityManager, column: 'repo_id' | 'container_id'): Promise<Map<number, Scan>> {
        const rows: Scan[] = await manager.query(
            `SELECT * FROM (
                 SELECT t_scan.*, ROW_NUMBER() OVER (PARTITION BY ${column} ORDER BY created_at DESC, id DESC) AS rang
                 FROM t_scan
                 WHERE ${column} IS NOT NULL
             ) AS derniers
             WHERE rang = 1`
        );
        const byTarget = new Map<number, Scan>();
        for (const row of rows) {
            const key = (row as unknown as Record<string, number>)[column];
            byTarget.set(key, row);
        }
        return byTarget;
    }

    /** Les politiques actives, toutes portées confondues, lues une fois. */
    async findActivePolicies(manager: EntityManager): Promise<GatePolicyRow[]> {
        return manager.findBy(GatePolicyRow, { isActive: Not(IsNull()) });
    }

    /**
     * Les problèmes ouverts, réduits aux colonnes que le verdict regarde.
     *
     * `evaluate` ne touche qu'une dizaine d'attributs : charger les lignes entières
     * ferait transiter les descriptions et les vecteurs CVSS d'un backlog à quatre
     * chiffres pour calculer un booléen.
     */
    async findOpenForGate(manager: EntityManager): Promise<Issue[]> {
        return manager
            .createQueryBuilder(Issue, 'issue')
            .select([
                'issue.id',
                'issue.repoId',
                'issue.containerId',
                'issue.type',
                'issue.severity',
                'issue.identifier',
                'issue.packageName',
                'issue.fixVersions',
                'issue.isKev',
                'issue.triageStatus',
                'issue.state'
            ])
            .where('issue.state = :state', { state: STATE_OPEN })
            .getMany();
    }
}
