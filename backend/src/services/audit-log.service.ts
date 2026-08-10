import { randomUUID } from 'node:crypto';
import { EntityManager } from 'typeorm';
import { computeEntryHash, rebuildChain, verifyChain } from '../domain/audit/audit-hash';
import { nowForDatabase } from '../domain/common/timestamp';
import { AuditLogRepository, AuditRow } from '../repositories/audit-log.repository';

/**
 * L'écriture et la vérification du journal d'audit.
 *
 * Volontairement limité aux actions d'administration et de sécurité — authentification,
 * gestion des comptes, cycle de vie des clés d'API, changements de réglages, triage,
 * déclenchement de scans, refus d'autorisation. Y consigner les consultations de pages
 * n'apporterait que du bruit, et un journal bruyant est un journal que personne ne lit.
 *
 * **`record()` ne lève jamais.** Un échec d'écriture du journal ne doit pas faire échouer
 * l'action qu'il décrit : le contraire donnerait à une table pleine le pouvoir
 * d'empêcher un administrateur de se connecter.
 */
export interface AuditRecord {
    operationType: string;
    resourceId: string;
    description: string;
    userId?: string | null;
    ipAddress?: string | null;
    userAgent?: string | null;
}

/**
 * Le dernier horodatage rendu, pour garantir qu'il croît strictement.
 *
 * `nowForDatabase()` a la milliseconde pour résolution : deux entrées écrites dans la
 * même milliseconde porteraient le même horodatage, et l'ordre entre elles ne serait
 * plus défini que par un UUID aléatoire. La chaîne serait alors construite dans un ordre
 * et relue dans un autre — la vérification échouerait sur un journal parfaitement
 * intact, ce qu'un test a montré sur cinq entrées écrites en boucle serrée.
 *
 * Avancer d'une milliseconde plutôt que d'attendre : le journal n'a pas besoin d'une
 * horloge exacte, il a besoin d'un ordre. Le décalage est borné par le débit d'écriture
 * et se résorbe dès la première pause.
 */
let lastIssued = '';

function monotonicNow(): string {
    const now = nowForDatabase();
    if (now > lastIssued) {
        lastIssued = now;
        return now;
    }
    lastIssued = advanceOneMillisecond(lastIssued);
    return lastIssued;
}

function advanceOneMillisecond(timestamp: string): string {
    const at = new Date(`${timestamp}Z`);
    at.setUTCMilliseconds(at.getUTCMilliseconds() + 1);
    const pad = (value: number, width = 2) => String(value).padStart(width, '0');
    return (
        `${at.getUTCFullYear()}-${pad(at.getUTCMonth() + 1)}-${pad(at.getUTCDate())}` +
        `T${pad(at.getUTCHours())}:${pad(at.getUTCMinutes())}:${pad(at.getUTCSeconds())}.${pad(at.getUTCMilliseconds(), 3)}`
    );
}

export class AuditLogService {
    constructor(private readonly entries = new AuditLogRepository()) {}

    async record(manager: EntityManager, entry: AuditRecord): Promise<void> {
        try {
            const previous = await this.entries.findLatest(manager);
            const row: AuditRow = {
                id: randomUUID(),
                // Posé ici et non laissé à un défaut de colonne : le hachage couvre
                // l'horodatage, et une valeur appliquée par la base après le calcul
                // ferait échouer chaque entrée à sa propre vérification.
                timestamp: monotonicNow(),
                operationType: entry.operationType,
                resourceId: String(entry.resourceId),
                // La colonne fait 255 : tronquer ici plutôt que laisser la base
                // refuser, sinon une description trop longue perdrait toute l'entrée.
                description: entry.description.slice(0, 255),
                userId: entry.userId ?? null,
                ipAddress: entry.ipAddress || null,
                userAgent: (entry.userAgent || '').slice(0, 255) || null,
                previousHash: previous?.entryHash ?? null,
                entryHash: null
            };
            row.entryHash = computeEntryHash(row);
            await this.entries.insert(manager, row);
        } catch {
            // Voir la note de classe : jamais au détriment de l'action décrite.
        }
    }

    async findRecent(manager: EntityManager, limit = 200): Promise<AuditRow[]> {
        return this.entries.findRecent(manager, limit);
    }

    /**
     * `null` si la chaîne est intacte, sinon la description de la première rupture.
     *
     * Lit toute la table : c'est une vérification délibérée, pas quelque chose qu'on
     * fait à chaque rendu de page.
     */
    async verify(manager: EntityManager): Promise<{ broken: string | null; unverifiable: number }> {
        return verifyChain(await this.entries.findAllOldestFirst(manager));
    }

    /**
     * Recalcule toute la chaîne. **L'opération de bascule, et rien d'autre.**
     *
     * Les entrées écrites par l'implémentation Python portent des empreintes calculées
     * sur une autre formule et ne se vérifient plus. Cette méthode les reprend une fois.
     *
     * À exécuter sous les yeux de quelqu'un : réécrire un journal d'intégrité est
     * exactement ce que ce journal existe pour rendre détectable. Elle n'est donc câblée
     * à aucune route et à aucun démarrage — c'est une commande d'exploitation.
     */
    async rebuild(manager: EntityManager): Promise<number> {
        const rows = rebuildChain(await this.entries.findAllOldestFirst(manager));
        for (const row of rows) {
            await this.entries.updateHashes(manager, row.id, row.previousHash, row.entryHash as string);
        }
        return rows.length;
    }
}
