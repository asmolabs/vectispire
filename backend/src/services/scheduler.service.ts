import { Injectable, Logger, OnApplicationShutdown } from '@nestjs/common';
import { Interval } from '@nestjs/schedule';
import { InjectEntityManager } from '@nestjs/typeorm';
import { EntityManager } from 'typeorm';
import { now } from '../domain/common/timestamp';
import { isTargetDue } from '../domain/scheduling/due';
import { Container, Repository as GitRepository, STATUS_QUEUED, Scan } from '../persistence/entities';
import { INSTANCE_ID, LeaderElectionService } from './leader-election.service';

/** À quelle fréquence chercher des cibles dues. La requête est deux lectures indexées. */
const TICK_MS = Number(process.env.ZANSHIN_SCHEDULER_TICK_SECONDS ?? '60') * 1000;

/**
 * Le rescan périodique.
 *
 * **C'est la boucle qui donne son sens au reste du produit.** Un scan manuel hebdomadaire
 * n'est pas de la gestion de posture, dans un outil dont la prémisse est que de nouvelles
 * vulnérabilités apparaissent dans du code inchangé.
 *
 * **Un scan ordonnancé et un scan manuel sont indiscernables en aval** : les deux posent
 * une ligne en file, que le même travailleur réclame et que le même ingesteur traite. Pas
 * de second chemin de code à tenir en phase.
 *
 * **`lastScheduledScanAt` est estampillé *avant* la mise en file.** L'estamper après
 * redéclencherait la même cible au tour suivant chaque fois qu'un scan dépasse un
 * intervalle.
 *
 * **Exclusif au meneur.** L'estampillage avant envoi protège contre un processus qui
 * ticke deux fois, et pas du tout contre deux processus qui tickent ensemble : sans
 * élection, chaque cible serait scannée autant de fois qu'il y a d'instances. Le
 * travailleur intégré, lui, reste par instance — une flotte dont les instances ne
 * réclameraient du travail qu'en détenant le bail resterait oisive derrière celle qui le
 * tient.
 */
@Injectable()
export class SchedulerService implements OnApplicationShutdown {
    private readonly logger = new Logger(SchedulerService.name);
    private busy = false;

    constructor(
        @InjectEntityManager() private readonly manager: EntityManager,
        private readonly election: LeaderElectionService
    ) {}

    @Interval(TICK_MS)
    async tick(): Promise<void> {
        if (!this.enabled() || this.busy) return;
        this.busy = true;
        try {
            await this.runOnce();
        } catch (error) {
            // **Ne lève jamais.** Une exception qui remonterait tuerait le minuteur et
            // mettrait fin en silence à tout scan automatique — la panne la plus difficile
            // à remarquer, puisque l'écran continue d'afficher des scans anciens.
            this.logger.error(`Tour d'ordonnancement échoué — reprise au tour suivant : ${(error as Error).message}`);
        } finally {
            this.busy = false;
        }
    }

    /** Un tour. Rend combien de scans ont été mis en file. */
    async runOnce(at: Date = now()): Promise<number> {
        // **Le même instant que l'échéance.** Le bail pris à `now()` alors que les cibles
        // sont jugées à `at` fait deux horloges dans un seul tour : celle du bail décide qui
        // écrit, celle de l'échéance décide quoi, et rien ne garantit qu'elles s'accordent.
        if (!(await this.holdLeadership(at))) return 0;

        const [repositories, containers] = await Promise.all([this.manager.find(GitRepository), this.manager.find(Container)]);
        let queued = 0;

        for (const repository of repositories.filter((target) => isTargetDue(target, at))) {
            queued += await this.queue({ repoId: repository.id, branch: repository.branch, subPath: repository.subPath }, at, () =>
                this.manager.update(GitRepository, { id: repository.id }, { lastScheduledScanAt: at })
            );
        }

        for (const container of containers.filter((target) => isTargetDue(target, at))) {
            // `n/a` et non une chaîne vide : la colonne est obligatoire, une image n'a pas
            // de branche, et c'est la valeur que pose déjà le déclenchement manuel — un
            // scan ordonnancé doit être indiscernable d'un scan manuel en aval.
            queued += await this.queue({ containerId: container.id, branch: 'n/a', subPath: null }, at, () =>
                this.manager.update(Container, { id: container.id }, { lastScheduledScanAt: at })
            );
        }

        if (queued > 0) this.logger.log(`Ordonnanceur : ${queued} scan(s) mis en file.`);
        return queued;
    }

    /**
     * Met une cible en file, si elle n'y est pas déjà.
     *
     * Le doublon est écarté ici comme il l'est au bouton de l'écran : une cible dont le
     * scan précédent n'a pas encore démarré n'a pas besoin d'un second, et les empiler
     * ferait grossir la file sans rien apprendre.
     */
    private async queue(
        target: { repoId?: number; containerId?: number; branch: string; subPath: string | null },
        at: Date,
        stamp: () => Promise<unknown>
    ): Promise<number> {
        const where = target.repoId !== undefined ? { repoId: target.repoId } : { containerId: target.containerId };
        try {
            // Estampillé avant, y compris quand la file est déjà servie : sans cela, une
            // cible dont le scan traîne serait réexaminée à chaque tour.
            await stamp();
            if ((await this.manager.countBy(Scan, { ...where, status: STATUS_QUEUED })) > 0) return 0;

            await this.manager.save(
                Scan,
                Object.assign(new Scan(), {
                    repoId: target.repoId ?? null,
                    containerId: target.containerId ?? null,
                    branch: target.branch,
                    subPath: target.subPath,
                    status: STATUS_QUEUED,
                    createdAt: at
                })
            );
            return 1;
        } catch (error) {
            // Une cible qui échoue ne doit pas emporter les autres : le tour suivant la
            // reverra, et les cibles saines auront été servies entre-temps.
            this.logger.error(`Mise en file impossible pour ${JSON.stringify(where)} : ${(error as Error).message}`);
            return 0;
        }
    }

    /**
     * Prend ou renouvelle le bail, et **échoue fermé**.
     *
     * Une instance qui ne peut pas atteindre la table des baux n'a pas le droit de
     * supposer qu'elle est seule. Sauter un tour coûte une minute de latence ; se croire
     * meneuse à tort coûte un scan dupliqué de chaque cible due.
     */
    private async holdLeadership(at: Date): Promise<boolean> {
        try {
            return await this.election.acquire(undefined, undefined, at);
        } catch (error) {
            this.logger.warn(`Bail d'ordonnancement inaccessible — tour sauté : ${(error as Error).message}`);
            return false;
        }
    }

    /**
     * Rend le bail à l'arrêt, pour qu'un successeur reprenne tout de suite au lieu
     * d'attendre l'expiration. Au mieux : un processus tué ne rend rien.
     */
    async onApplicationShutdown(): Promise<void> {
        try {
            if (await this.election.release()) this.logger.log(`L'instance ${INSTANCE_ID} a rendu le bail d'ordonnancement.`);
        } catch {
            // L'expiration est le filet, et c'est exactement pourquoi rien ne dépend de ce
            // passage.
        }
    }

    /** Activé par défaut : un opérateur qui configure un intervalle attend qu'il soit honoré. */
    private enabled(): boolean {
        return process.env.ZANSHIN_SCHEDULER_ENABLED !== 'false';
    }
}
