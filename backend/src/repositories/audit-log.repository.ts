import { EntityManager } from 'typeorm';
import { AuditEntryForVerification } from '../domain/audit/audit-hash';
import { AuditLog } from '../persistence/entities';

/**
 * Accès au journal d'audit.
 *
 * **Ce fichier écrivait du SQL brut, et n'a plus à le faire.** La raison était mesurée :
 * TypeORM ré-hydratait les colonnes de date en interprétant un texte naïf comme une heure
 * locale, si bien qu'une entrée relue à travers une entité revenait décalée — et comme
 * l'empreinte de la chaîne d'intégrité couvre l'horodatage, chaque entrée échouait à sa
 * propre vérification. Le journal se déclarait falsifié alors que rien ne l'avait été.
 *
 * La cause était le type de colonne, pas l'ORM : en `timestamptz`, le pilote rend un
 * instant absolu et l'hydratation est fidèle. Le SQL brut disparaît donc, et avec lui les
 * marqueurs `$1` propres à PostgreSQL, `ILIKE` qui n'existe que là, et les noms de table
 * écrits en dur — ce qui rend ce chemin portable à MySQL sans rien y ajouter.
 *
 * `audit-log.integration-spec.ts` vérifie ce qui compte : une entrée écrite puis relue se
 * vérifie, et une entrée modifiée en base ne se vérifie plus.
 */

export interface AuditRow extends AuditEntryForVerification {
    id: string;
}

export interface AuditFilters {
    operationType?: string | null;
    userId?: string | null;
    /** Recherche libre sur la description. */
    search?: string | null;
}

export class AuditLogRepository {
    /**
     * La dernière entrée écrite — celle dont l'empreinte devient le maillon suivant.
     *
     * **Un tri et une ligne, et non toute la table.** Cette méthode suivait la chaîne
     * maillon par maillon, ce qui obligeait à charger le journal entier à *chaque écriture* :
     * mesuré à 1,6 ms sur 200 entrées et 17,1 ms sur 3 000 — linéaire, et payé par chaque
     * connexion, chaque triage, chaque changement de réglage. Un journal d'audit est fait
     * pour durer ; à cent mille entrées, ordinaire au bout de quelques mois, chaque action
     * auditée aurait traîné une demi-seconde et alloué la table entière en mémoire.
     *
     * Le tri est fiable ici parce que `monotonicNow()` garantit des horodatages
     * **strictement croissants** dans un processus : le cas que ce parcours protégeait —
     * deux entrées de la même milliseconde départagées par un UUID aléatoire, donc chaînées
     * dans un ordre et relues dans un autre — ne peut plus se produire. Les deux parades
     * existaient en même temps, et celle-ci coûtait un parcours complet.
     *
     * **Ce qu'aucune des deux ne règle**, et qui reste une limite connue : deux instances
     * web écrivant au même instant lisent la même queue et produisent deux entrées portant
     * la même précédente. La chaîne fourche, et `verifyChain` le signale comme une rupture
     * sur un journal pourtant intact. Le parcours complet ne protégeait pas davantage de ce
     * cas — il le rendait seulement plus cher. Le refermer demande de sérialiser l'écriture
     * sur la queue, ce qui est un changement de conception à part entière.
     */
    async findLatest(manager: EntityManager): Promise<AuditRow | null> {
        const rows = await manager.find(AuditLog, { order: { timestamp: 'DESC', id: 'DESC' }, take: 1 });
        return rows[0] ?? null;
    }

    async insert(manager: EntityManager, row: AuditRow): Promise<void> {
        await manager.save(AuditLog, Object.assign(new AuditLog(), row));
    }

    /** Les plus récentes d'abord : ce que l'écran affiche. */
    async findRecent(manager: EntityManager, limit = 200): Promise<AuditRow[]> {
        return manager.find(AuditLog, { order: { timestamp: 'DESC', id: 'DESC' }, take: limit });
    }

    /**
     * Une page du journal, filtrée.
     *
     * Le constructeur de requêtes plutôt qu'une concaténation : les valeurs passent par
     * des paramètres nommés, et la comparaison insensible à la casse s'écrit avec `LOWER`
     * de part et d'autre — `ILIKE` n'existe qu'en PostgreSQL.
     */
    async findFiltered(
        manager: EntityManager,
        filters: AuditFilters,
        limit: number,
        offset: number
    ): Promise<{ rows: AuditRow[]; total: number }> {
        const query = manager.createQueryBuilder(AuditLog, 'entry');

        if (filters.operationType) query.andWhere('entry.operation_type = :operationType', { operationType: filters.operationType });
        if (filters.userId) query.andWhere('entry.user_id = :userId', { userId: filters.userId });
        if (filters.search) {
            // `%` et `_` échappés : sans cela une recherche contenant « % » rendrait tout,
            // ce qui se lit comme un filtre qui ne marche pas.
            const escaped = filters.search.replace(/[\\%_]/g, (match) => `\\${match}`);
            query.andWhere('LOWER(entry.description) LIKE LOWER(:search)', { search: `%${escaped}%` });
        }

        const [rows, total] = await query
            .orderBy('entry.timestamp', 'DESC')
            .addOrderBy('entry.id', 'DESC')
            .skip(offset)
            .take(limit)
            .getManyAndCount();
        return { rows, total };
    }

    /** Les types d'opération réellement présents, pour que le filtre ne propose pas des
     *  valeurs qui ne rendraient rien. */
    async distinctOperationTypes(manager: EntityManager): Promise<string[]> {
        const rows: { operationType: string | null }[] = await manager
            .createQueryBuilder(AuditLog, 'entry')
            .select('DISTINCT entry.operation_type', 'operationType')
            .where('entry.operation_type IS NOT NULL')
            .getRawMany();
        return rows
            .map((row) => row.operationType)
            .filter((value): value is string => Boolean(value))
            .sort();
    }

    /**
     * Toute la table, dans l'ordre où la chaîne a été construite.
     *
     * Obtenu en **suivant les maillons** — de l'entrée sans précédente vers la suivante,
     * et ainsi de suite — et non par un tri. C'est ici que le parcours a sa place : la
     * vérification est une opération délibérée, rare, et son travail *est* de reconstituer
     * l'ordre dans lequel la chaîne a été construite plutôt que de le supposer.
     *
     * Les entrées qu'aucun maillon n'atteint sont ajoutées à la fin, triées par
     * horodatage. C'est délibéré : elles sont soit antérieures au chaînage, soit le signe
     * d'une rupture, et dans les deux cas c'est `verifyChain` qui doit le dire — les taire
     * ici masquerait précisément ce que le journal existe pour révéler.
     */
    async findAllOldestFirst(manager: EntityManager): Promise<AuditRow[]> {
        const rows = await manager.find(AuditLog, { order: { timestamp: 'ASC', id: 'ASC' } });
        if (rows.length === 0) return rows;

        const byPrevious = new Map<string, AuditRow>();
        for (const row of rows) {
            if (row.entryHash) byPrevious.set(row.previousHash ?? '', row);
        }

        const chained: AuditRow[] = [];
        const seen = new Set<string>();
        let current = byPrevious.get('');
        while (current && current.entryHash && !seen.has(current.id)) {
            chained.push(current);
            seen.add(current.id);
            current = byPrevious.get(current.entryHash);
        }

        const unreachable = rows.filter((row) => !seen.has(row.id));
        return [...chained, ...unreachable];
    }

    async updateHashes(manager: EntityManager, id: string, previousHash: string | null, entryHash: string): Promise<void> {
        await manager.update(AuditLog, { id }, { previousHash, entryHash });
    }
}
