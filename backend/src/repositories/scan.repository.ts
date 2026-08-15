import { EntityManager, In, IsNull, LessThan } from 'typeorm';
import { now } from '../domain/common/timestamp';
import { CLAIM_ATTEMPTS, LEASE_EXHAUSTED_MESSAGE, afterLapse, leaseUntil } from '../domain/scans/queue-rules';
import { CAPABILITIES } from '../persistence/dialects';
import { DIALECT } from '../persistence/column-types';
import { Scan, STATUS_FAILED, STATUS_QUEUED, STATUS_RUNNING } from '../persistence/entities';

/**
 * L'accès à la file de scans, dont la réclamation est le cœur.
 *
 * **La réclamation est transactionnelle.** `SELECT … FOR UPDATE SKIP LOCKED` donne à
 * cette transaction la propriété exclusive des lignes sélectionnées, et laisse un
 * réclamant concurrent *passer outre* au lieu de bloquer — c'est ce qui permet à
 * plusieurs instances de partager une file sans se sérialiser sur la ligne la plus
 * ancienne. Le changement de statut et la libération du verrou ont lieu dans le même
 * commit : il n'existe aucune fenêtre où une ligne serait réclamée sans le dire.
 *
 * **La file est routée.** Un scan peut exiger une étiquette d'agent ; le filtre vit dans
 * la requête verrouillante elle-même, jamais après. Prendre puis rendre ce qui ne convient
 * pas verrouillerait des lignes destinées à d'autres et les affamerait le temps de la
 * transaction — c'est exactement le défaut décrit au paragraphe suivant, sous un autre
 * déguisement.
 *
 * **Demander exactement ce dont on a besoin, et réessayer.** L'idée évidente — verrouiller
 * une fenêtre plus large puis la rogner — a été essayée et faisait échouer PostgreSQL sur
 * les tests mêmes que MySQL échouait : un réclamant qui verrouille des lignes qu'il ne
 * prendra pas affame les autres aussi longtemps qu'il les tient.
 */
export class ScanRepository {
    /** Combien de scans tournent, pour en déduire la capacité restante. */
    async countRunning(manager: EntityManager): Promise<number> {
        return manager.countBy(Scan, { status: STATUS_RUNNING });
    }

    async countQueued(manager: EntityManager): Promise<number> {
        return manager.countBy(Scan, { status: STATUS_QUEUED });
    }

    /**
     * Réclame jusqu'à `limit` scans en attente pour ce travailleur.
     *
     * **À appeler dans une transaction.** Le verrou posé par `FOR UPDATE` ne vaut que
     * jusqu'au commit ; hors transaction, chaque requête committe seule et la garantie
     * disparaît sans que rien ne le signale.
     */
    async claim(manager: EntityManager, limit: number, worker: string | null, agentLabels: string[] = []): Promise<Scan[]> {
        if (limit <= 0) return [];

        const claimed: Scan[] = [];
        for (let attempt = 0; attempt < CLAIM_ATTEMPTS; attempt += 1) {
            const wanted = limit - claimed.length;
            const batch = await this.takeBatch(manager, wanted, agentLabels);

            if (batch.length > 0) {
                const claimedAt = now();
                for (const scan of batch) {
                    scan.status = STATUS_RUNNING;
                    scan.claimedBy = worker;
                    scan.claimedAt = claimedAt;
                    scan.leaseExpiresAt = leaseUntil(claimedAt);
                    scan.attempts += 1;
                }
                await manager.save(Scan, batch);
                claimed.push(...batch);
            }

            if (claimed.length >= limit) break;
            // Rien à prendre : la file est vide, *tout est verrouillé ailleurs*, ou rien
            // n'est destiné à cet agent. Un tour de plus distingue le deuxième cas des
            // autres, et la boucle est bornée.
            if (batch.length === 0 && (await this.countQueued(manager)) === 0) break;
        }
        return claimed;
    }

    /**
     * Les lignes que ce réclamant a le droit de prendre — **et qu'il a effectivement prises**.
     *
     * Deux stratégies, choisies par une capacité du moteur et non par son nom :
     *
     * - **Verrou pessimiste** là où il existe. `FOR UPDATE SKIP LOCKED` donne la propriété
     *   exclusive des lignes sélectionnées et laisse un concurrent passer outre au lieu de
     *   bloquer, ce qui permet à plusieurs instances de partager une file sans se sérialiser
     *   sur la ligne la plus ancienne.
     * - **Reprise conditionnelle** là où il n'existe pas. `better-sqlite3` **refuse**
     *   `FOR UPDATE` — `LockNotSupportedOnGivenDriverError` — au lieu de l'accepter et de
     *   l'ignorer comme le fait l'autre pilote SQLite. Le refus est bruyant, donc préférable,
     *   mais il faut une autre voie : on sélectionne des candidates, puis on ne garde que
     *   celles dont la mise à jour a réellement mordu, `status = 'pending'` faisant office de
     *   garde. Une ligne prise entre-temps par quelqu'un d'autre rend `affected = 0` et sort
     *   du lot.
     *
     * **Le drapeau existait et personne ne le lisait.** Il décrivait le comportement sans
     * l'obtenir — la même famille de défaut que ce dépôt passe son temps à corriger.
     */
    private async takeBatch(manager: EntityManager, wanted: number, agentLabels: string[]): Promise<Scan[]> {
        const transactional = CAPABILITIES[DIALECT].canClaimTransactionally;

        const query = manager
            .createQueryBuilder(Scan, 'scan')
            .where('scan.status = :status', { status: STATUS_QUEUED })
            // **Le filtre est ici, dans la requête verrouillante.** Le poser après coup
            // — prendre puis rendre ce qui ne convient pas — verrouillerait des lignes
            // destinées à d'autres et les affamerait le temps de la transaction, ce qui
            // est le défaut qu'on a déjà payé une fois sur cette même requête.
            .andWhere(
                agentLabels.length === 0
                    ? 'scan.required_agent_label IS NULL'
                    : '(scan.required_agent_label IS NULL OR scan.required_agent_label IN (:...agentLabels))',
                agentLabels.length === 0 ? {} : { agentLabels }
            )
            .orderBy('scan.created_at', 'ASC')
            .addOrderBy('scan.id', 'ASC')
            .limit(wanted);

        if (transactional) {
            const locked = await query.setLock('pessimistic_write').setOnLocked('skip_locked').getMany();
            return locked;
        }

        const candidates = await query.getMany();
        const taken: Scan[] = [];
        for (const scan of candidates) {
            // `status` en condition : c'est lui qui rend la reprise sûre sans verrou.
            const result = await manager.update(Scan, { id: scan.id, status: STATUS_QUEUED }, { status: STATUS_QUEUED });
            if (result.affected === 1) taken.push(scan);
        }
        return taken;
    }

    /**
     * Rend à la file les scans dont le bail a expiré, ou les fait échouer pour de bon.
     *
     * Un bail lapse quand un travailleur cesse de donner signe : le processus est mort, la
     * machine a disparu, le réseau s'est coupé. **Rien n'est arrêté ici** — le travail
     * tourne peut-être encore ailleurs, et rien dans ce processus ne peut tuer un fil sur
     * une autre machine. La ligne redevient réclamable, et `stillOwned` refusera ensuite
     * les résultats du travailleur déchu.
     */
    async reclaimExpiredLeases(manager: EntityManager, asOf: Date = now()): Promise<{ requeued: Scan[]; failed: Scan[] }> {
        // Filtré en SQL et sur un index : la version qui chargeait tous les scans en cours
        // pour comparer en mémoire ne tenait que tant que la colonne était du texte.
        const stalled = await manager.find(Scan, {
            where: [
                { status: STATUS_RUNNING, leaseExpiresAt: LessThan(asOf) },
                { status: STATUS_RUNNING, leaseExpiresAt: IsNull() }
            ]
        });
        if (stalled.length === 0) return { requeued: [], failed: [] };

        const requeued: Scan[] = [];
        const failed: Scan[] = [];
        for (const scan of stalled) {
            if (afterLapse(scan.attempts) === 'fail') {
                scan.status = STATUS_FAILED;
                scan.error = LEASE_EXHAUSTED_MESSAGE;
                failed.push(scan);
            } else {
                scan.status = STATUS_QUEUED;
                requeued.push(scan);
            }
            // Dans les deux cas le bail tombe : un scan en échec qui garderait un bail
            // serait repris par la reprise suivante.
            scan.claimedBy = null;
            scan.claimedAt = null;
            scan.leaseExpiresAt = null;
        }

        await manager.save(Scan, stalled);
        return { requeued, failed };
    }

    /**
     * Ce travailleur détient-il encore ce scan ?
     *
     * Appelé avant d'écrire un résultat. Sans cette vérification, un travailleur dont le
     * bail a expiré — et dont le scan a été repris par un autre — écraserait le travail
     * de son successeur en rendant des résultats périmés.
     */
    async stillOwned(manager: EntityManager, scanId: number, worker: string | null): Promise<boolean> {
        const scan = await manager.findOne(Scan, { where: { id: scanId }, select: { id: true, status: true, claimedBy: true } });
        return scan !== null && scan.status === STATUS_RUNNING && scan.claimedBy === worker;
    }

    /** Prolonge le bail d'un scan qui progresse — l'inverse de le laisser lapser. */
    async renewLease(manager: EntityManager, scanId: number, worker: string | null): Promise<boolean> {
        const at = now();
        const result = await manager.update(
            Scan,
            { id: scanId, status: STATUS_RUNNING, claimedBy: worker },
            { leaseExpiresAt: leaseUntil(at) }
        );
        return (result.affected ?? 0) > 0;
    }

    async findByStatus(manager: EntityManager, statuses: string[]): Promise<Scan[]> {
        return manager.find(Scan, { where: { status: In(statuses) }, order: { createdAt: 'ASC', id: 'ASC' } });
    }
}
