import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { Interval } from '@nestjs/schedule';
import { hostname } from 'node:os';
import { randomUUID } from 'node:crypto';
import { parseAgentLabels } from '../domain/agents/targeting';
import { ScanDispatcherService } from './scan-dispatcher.service';

/**
 * Le travailleur intégré : il tourne dans le processus de Zanshin et vide la file.
 *
 * **Il n'a rien de privilégié.** Il réclame comme le ferait un agent distant, avec le même
 * bail et la même vérification de propriété. C'est ce qui fait qu'ajouter un agent ne
 * demande aucun changement ici : la file ne sait pas qui la sert.
 *
 * **Un seul tour à la fois.** `Interval` rappelle la méthode même si la précédente n'a pas
 * rendu la main ; sans ce garde, un scan lent verrait s'empiler des tours qui réclameraient
 * tous en parallèle et dépasseraient la limite de parallélisme que le tour précédent avait
 * calculée.
 */
@Injectable()
export class ScanWorkerService implements OnModuleInit {
    private readonly logger = new Logger(ScanWorkerService.name);

    /**
     * L'identité de ce travailleur.
     *
     * Nom de machine **et** identifiant unique : le nom seul ne distinguerait pas deux
     * instances sur le même hôte — cas ordinaire d'un déploiement conteneurisé — et deux
     * travailleurs partageant une identité se voleraient mutuellement leurs baux sans que
     * `stillOwned` puisse s'en apercevoir.
     */
    private readonly worker = `${hostname()}/${randomUUID().slice(0, 8)}`;

    private busy = false;

    /**
     * Les étiquettes de cet hôte, pour le ciblage des scans.
     *
     * **Vides par défaut, donc il ne prend que le travail sans exigence.** L'inverse — « le
     * travailleur intégré correspond à tout » — rendrait le ciblage inopérant sur toute
     * installation mono-instance, c'est-à-dire la plupart. Un opérateur qui veut lui confier
     * des cibles étiquetées le déclare : `ZANSHIN_WORKER_LABELS=production,interne`.
     */
    private labels(): string[] {
        return parseAgentLabels(process.env.ZANSHIN_WORKER_LABELS);
    }

    constructor(private readonly dispatcher: ScanDispatcherService) {}

    onModuleInit(): void {
        if (this.enabled()) this.logger.log(`Travailleur de scan « ${this.worker} », ${this.maxConcurrent()} scan(s) en parallèle.`);
        else this.logger.log('Travailleur de scan désactivé : la file ne sera servie que par des agents distants.');
    }

    @Interval(15_000)
    async tick(): Promise<void> {
        if (!this.enabled() || this.busy) return;

        this.busy = true;
        try {
            const result = await this.dispatcher.dispatch(this.worker, this.maxConcurrent(), this.labels());
            if (result.claimed > 0) {
                this.logger.log(`${result.claimed} scan(s) réclamé(s) — ${result.completed} terminé(s), ${result.failed} en échec.`);
            }
        } catch (error) {
            // Journalisé et avalé : une erreur ici ne doit pas arrêter l'intervalle, sinon
            // une panne passagère de la base arrêterait la file jusqu'au redémarrage.
            this.logger.error(`Le tour de distribution a échoué : ${(error as Error).message}`);
        } finally {
            this.busy = false;
        }
    }

    /**
     * Désactivable, pour le déploiement où le plan de contrôle ne scanne pas lui-même.
     *
     * Lu à chaque tour et non au démarrage : c'est ce qui permet de l'arrêter sans
     * redémarrer, et le coût d'une lecture d'environnement toutes les quinze secondes est
     * nul.
     */
    private enabled(): boolean {
        return process.env.ZANSHIN_EMBEDDED_WORKER !== 'false';
    }

    private maxConcurrent(): number {
        const configured = Number(process.env.ZANSHIN_SCAN_MAX_CONCURRENT ?? 2);
        return Number.isFinite(configured) && configured > 0 ? Math.trunc(configured) : 2;
    }
}
