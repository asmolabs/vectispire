import { Injectable, Logger } from '@nestjs/common';
import { InjectEntityManager } from '@nestjs/typeorm';
import { EntityManager } from 'typeorm';
import { randomUUID } from 'node:crypto';
import { now } from '../domain/common/timestamp';
import { LeaderLease } from '../persistence/entities';

/** Le nom du bail de l'ordonnanceur. Une ligne par tâche exclusive. */
export const JOB_SCHEDULER = 'scheduler';

/**
 * Combien de temps un bail tient sans renouvellement.
 *
 * Confortablement plus long que le tour qui le renouvelle, pour qu'un tour lent ne remette
 * pas le travail à quelqu'un d'autre — et assez court pour qu'un meneur mort soit remplacé
 * en deux minutes plutôt qu'en une heure.
 */
export const LEASE_SECONDS = Number(process.env.ZANSHIN_LEADER_LEASE_SECONDS ?? '180');

/**
 * Ce processus, pour la durée de ce processus.
 *
 * **Pas le nom de machine** : deux instances sur un même hôte est un déploiement que
 * quelqu'un tentera, et un nom de machine ne saurait pas les distinguer. Pas persisté non
 * plus — une instance redémarrée est un nouveau détenteur, ce qui est exactement juste
 * puisqu'elle a oublié ce qu'elle était en train de faire.
 */
export const INSTANCE_ID = randomUUID().replace(/-/g, '');

/**
 * Prendre, tenir et perdre le bail qui rend un travail à propriétaire unique.
 *
 * Trois opérations, toutes bâties sur la même primitive : un `UPDATE` conditionnel dont le
 * nombre de lignes touchées désigne le gagnant. Cette primitive est plus faible que
 * `SELECT … FOR UPDATE SKIP LOCKED`, et elle suffit ici parce que ce qu'elle protège est
 * périodique et presque idempotent : deux instances se croyant brièvement meneuses font un
 * tour dupliqué, pas une ligne corrompue, et le tour suivant tranche.
 *
 * **Ce que « meneur » couvre, et ce qu'il ne couvre délibérément pas.** Le travail exclusif
 * est la part du tour qui a un effet *par période* — dépêcher les cibles dues, la purge,
 * l'expiration des triages, le relais d'outbox, la reprise des scans abandonnés. Pas la
 * part qui est par instance par nature : chaque instance doit continuer de réclamer du
 * travail pour son propre travailleur intégré, sinon une flotte resterait oisive derrière
 * celle qui détient le bail.
 */
@Injectable()
export class LeaderElectionService {
    private readonly logger = new Logger(LeaderElectionService.name);

    constructor(@InjectEntityManager() private readonly manager: EntityManager) {}

    /**
     * Prend ou renouvelle le bail. Rend si ce processus le détient.
     *
     * Trois cas, dans une seule fonction parce que l'appelant se moque duquel il s'agit :
     * personne ne l'a jamais tenu, quelqu'un le tient mais l'a laissé expirer, ou nous le
     * tenons déjà et le renouvelons. **Le renouvellement est ce qui rend le meneur stable**
     * — un meneur qui devrait reconquérir à chaque tour ferait tourner le travail dans la
     * flotte sans raison.
     */
    async acquire(name = JOB_SCHEDULER, holder = INSTANCE_ID, at: Date = now()): Promise<boolean> {
        const expiresAt = new Date(at.getTime() + LEASE_SECONDS * 1000);
        const lease = await this.manager.findOneBy(LeaderLease, { name });

        if (lease === null) return this.create(name, holder, at, expiresAt);

        const isMine = lease.holder === holder;
        const isExpired = lease.expiresAt === null || lease.expiresAt <= at;
        if (!isMine && !isExpired) return false;

        // Conditionné sur le détenteur **et** sur l'expiration qu'on vient de lire : si une
        // autre instance a pris le bail entre la lecture et cet UPDATE, son nombre de
        // lignes est zéro et nous perdons — au lieu de voler un bail légitimement tenu.
        const query = this.manager
            .createQueryBuilder()
            .update(LeaderLease)
            .set({
                holder,
                expiresAt,
                updatedAt: at,
                ...(isMine ? {} : { acquiredAt: at })
            })
            .where('name = :name', { name });

        if (lease.holder === null) query.andWhere('holder IS NULL');
        else query.andWhere('holder = :previous', { previous: lease.holder });

        if (!isMine) {
            if (lease.expiresAt === null) query.andWhere('expires_at IS NULL');
            else query.andWhere('expires_at = :expiry', { expiry: lease.expiresAt });
        }

        const updated = (await query.execute()).affected ?? 0;
        if (updated > 0 && !isMine) this.logger.log(`L'instance ${holder} a pris le bail « ${name} ».`);
        return updated > 0;
    }

    /**
     * Première acquisition.
     *
     * Deux instances démarrées ensemble tentent toutes deux ceci, et **c'est la clé
     * primaire qui arbitre** : la perdante attrape la violation de contrainte et
     * réessaiera au tour suivant.
     */
    private async create(name: string, holder: string, at: Date, expiresAt: Date): Promise<boolean> {
        try {
            await this.manager.insert(LeaderLease, { name, holder, acquiredAt: at, expiresAt, updatedAt: at });
            this.logger.log(`L'instance ${holder} a pris le bail « ${name} ».`);
            return true;
        } catch {
            return false;
        }
    }

    /**
     * Rend le bail, pour qu'un successeur le prenne tout de suite au lieu d'attendre
     * l'expiration.
     *
     * Appelé à l'arrêt. Au mieux par nature — un processus tué ne rend rien, ce qui est
     * précisément pourquoi l'expiration existe et pourquoi rien ne dépend de ce passage.
     */
    async release(name = JOB_SCHEDULER, holder = INSTANCE_ID): Promise<boolean> {
        const result = await this.manager
            .createQueryBuilder()
            .update(LeaderLease)
            .set({ holder: null, expiresAt: null, updatedAt: now() })
            .where('name = :name AND holder = :holder', { name, holder })
            .execute();
        return (result.affected ?? 0) > 0;
    }

    /**
     * Qui détient le bail à cet instant, ou `null` s'il est libre ou périmé.
     *
     * Pour l'affichage et le diagnostic : « il ne se passe rien » est une question à
     * laquelle ceci répond.
     */
    async currentHolder(name = JOB_SCHEDULER, at: Date = now()): Promise<string | null> {
        const lease = await this.manager.findOneBy(LeaderLease, { name });
        if (!lease?.holder) return null;
        if (lease.expiresAt === null || lease.expiresAt <= at) return null;
        return lease.holder;
    }

    /** Ce processus détient-il le bail, sans le prendre ? */
    async isLeader(name = JOB_SCHEDULER, holder = INSTANCE_ID, at: Date = now()): Promise<boolean> {
        return (await this.currentHolder(name, at)) === holder;
    }
}
