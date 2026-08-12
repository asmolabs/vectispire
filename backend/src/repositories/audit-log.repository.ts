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
     * **La queue de la liste chaînée, et non le maximum d'un tri.** Trier par horodatage
     * puis par identifiant paraît suffisant et ne l'est pas : deux entrées écrites dans la
     * même milliseconde se départagent alors par un UUID aléatoire, si bien que l'ordre
     * dans lequel la chaîne est *construite* peut différer de celui dans lequel elle est
     * *relue*. La vérification échoue alors sur un journal parfaitement intact — c'est ce
     * qu'un test a montré, sur cinq entrées écrites en boucle serrée.
     *
     * La chaîne définit son propre ordre : c'est elle qu'on suit.
     */
    async findLatest(manager: EntityManager): Promise<AuditRow | null> {
        const ordered = await this.findAllOldestFirst(manager);
        return ordered[ordered.length - 1] ?? null;
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
     * et ainsi de suite — et non par un tri, pour la raison exposée sur `findLatest`.
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
