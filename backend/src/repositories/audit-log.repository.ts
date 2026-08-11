import { EntityManager } from 'typeorm';
import { AuditEntryForVerification } from '../domain/audit/audit-hash';

/**
 * Accès au journal d'audit, **en SQL brut et non par une entité**.
 *
 * Ce n'est pas une préférence de style, c'est une contrainte mesurée. TypeORM
 * ré-hydrate les colonnes de date pour son compte : il construit un `Date` en
 * interprétant le texte naïf de la base comme une heure *locale*. Sur une machine en
 * UTC+2, une entrée relue à travers une entité revient décalée de deux heures — et
 * comme l'empreinte de la chaîne d'intégrité couvre l'horodatage, chaque entrée
 * échouerait à sa propre vérification. Le journal se déclarerait falsifié alors que
 * rien ne l'aurait été.
 *
 * Une requête brute contourne cette hydratation : le parseur de `pg`
 * (`persistence/pg-types.ts`) rend le texte exact que la base contient, et c'est ce
 * texte qui entre dans le hachage.
 *
 * `pg-types.integration-spec.ts` vérifie la première moitié de cette chaîne (le pilote
 * rend du texte), `audit-log.integration-spec.ts` la seconde (une entrée écrite puis
 * relue se vérifie).
 */

export interface AuditRow extends AuditEntryForVerification {
    id: string;
}

/** Les colonnes, dans l'ordre où le hachage les consomme. */
const COLUMNS = `id,
    previous_hash AS "previousHash",
    entry_hash AS "entryHash",
    timestamp,
    operation_type AS "operationType",
    resource_id AS "resourceId",
    user_id AS "userId",
    ip_address AS "ipAddress",
    user_agent AS "userAgent",
    description`;

export class AuditLogRepository {
    /**
     * La dernière entrée écrite — celle dont l'empreinte devient le maillon suivant.
     *
     * **La queue de la liste chaînée, et non le maximum d'un tri.** Trier par
     * horodatage puis par identifiant paraît suffisant et ne l'est pas : deux entrées
     * écrites dans la même milliseconde se départagent alors par un UUID aléatoire, si
     * bien que l'ordre dans lequel la chaîne est *construite* peut différer de celui
     * dans lequel elle est *relue*. La vérification échoue alors sur un journal
     * parfaitement intact — c'est ce qu'un test a montré, sur cinq entrées écrites en
     * boucle serrée.
     *
     * La chaîne définit son propre ordre : c'est elle qu'on suit.
     */
    async findLatest(manager: EntityManager): Promise<AuditRow | null> {
        const ordered = await this.findAllOldestFirst(manager);
        return ordered[ordered.length - 1] ?? null;
    }

    async insert(manager: EntityManager, row: AuditRow): Promise<void> {
        await manager.query(
            `INSERT INTO audit_logs (id, description, operation_type, resource_id, timestamp, user_id, ip_address, user_agent, previous_hash, entry_hash)
             VALUES ($1, $2, $3, $4, $5::timestamp, $6, $7, $8, $9, $10)`,
            [row.id, row.description, row.operationType, row.resourceId, row.timestamp, row.userId, row.ipAddress, row.userAgent, row.previousHash, row.entryHash]
        );
    }

    /** Les plus récentes d'abord : ce que l'écran affiche. */
    async findRecent(manager: EntityManager, limit = 200): Promise<AuditRow[]> {
        return manager.query(`SELECT ${COLUMNS} FROM audit_logs ORDER BY timestamp DESC, id DESC LIMIT $1`, [limit]);
    }

    /**
     * Une page du journal, filtrée.
     *
     * Les clauses sont assemblées à partir d'un vocabulaire fermé et les valeurs passent
     * toujours par des paramètres — ce fichier écrit du SQL à la main, donc la seule
     * discipline qui tienne est de ne jamais interpoler ce qui vient de l'appelant.
     */
    async findFiltered(
        manager: EntityManager,
        filters: AuditFilters,
        limit: number,
        offset: number
    ): Promise<{ rows: AuditRow[]; total: number }> {
        const { clause, parameters } = buildWhere(filters);
        const [rows, counted] = await Promise.all([
            manager.query(
                `SELECT ${COLUMNS} FROM audit_logs ${clause} ORDER BY timestamp DESC, id DESC LIMIT $${parameters.length + 1} OFFSET $${parameters.length + 2}`,
                [...parameters, limit, offset]
            ),
            manager.query(`SELECT COUNT(*) AS total FROM audit_logs ${clause}`, parameters)
        ]);
        return { rows, total: Number(counted[0].total) };
    }

    /** Les types d'opération réellement présents, pour que le filtre ne propose pas des
     *  valeurs qui ne rendraient rien. */
    async distinctOperationTypes(manager: EntityManager): Promise<string[]> {
        const rows: { operationType: string | null }[] = await manager.query(
            'SELECT DISTINCT operation_type AS "operationType" FROM audit_logs WHERE operation_type IS NOT NULL ORDER BY 1'
        );
        return rows.map((row) => row.operationType!).filter(Boolean);
    }

    /**
     * Toute la table, dans l'ordre où la chaîne a été construite.
     *
     * Obtenu en **suivant les maillons** — de l'entrée sans précédente vers la suivante,
     * et ainsi de suite — et non par un tri, pour la raison exposée sur `findLatest`.
     *
     * Les entrées qu'aucun maillon n'atteint sont ajoutées à la fin, triées par
     * horodatage. C'est délibéré : elles sont soit antérieures au chaînage, soit le
     * signe d'une rupture, et dans les deux cas c'est `verifyChain` qui doit le dire —
     * les taire ici masquerait précisément ce que le journal existe pour révéler.
     */
    async findAllOldestFirst(manager: EntityManager): Promise<AuditRow[]> {
        const rows: AuditRow[] = await manager.query(`SELECT ${COLUMNS} FROM audit_logs ORDER BY timestamp ASC, id ASC`);
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
        await manager.query('UPDATE audit_logs SET previous_hash = $1, entry_hash = $2 WHERE id = $3', [previousHash, entryHash, id]);
    }
}

export interface AuditFilters {
    operationType?: string | null;
    userId?: string | null;
    /** Recherche libre sur la description. */
    search?: string | null;
}

function buildWhere(filters: AuditFilters): { clause: string; parameters: unknown[] } {
    const conditions: string[] = [];
    const parameters: unknown[] = [];

    if (filters.operationType) {
        parameters.push(filters.operationType);
        conditions.push(`operation_type = $${parameters.length}`);
    }
    if (filters.userId) {
        parameters.push(filters.userId);
        conditions.push(`user_id = $${parameters.length}`);
    }
    if (filters.search) {
        // `%` et `_` échappés : sans cela une recherche sur « 100_% » rendrait tout, ce
        // qui se lit comme un filtre qui ne marche pas.
        parameters.push(`%${filters.search.replace(/[\\%_]/g, (match) => `\\${match}`)}%`);
        conditions.push(`description ILIKE $${parameters.length}`);
    }

    return { clause: conditions.length ? `WHERE ${conditions.join(' AND ')}` : '', parameters };
}
