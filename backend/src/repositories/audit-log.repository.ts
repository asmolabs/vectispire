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
