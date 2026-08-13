import { Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { RetentionService } from './retention.service';

/**
 * Les travaux d'entretien périodiques.
 *
 * **Une heure, et non chaque tour d'ordonnanceur.** La purge parcourt tous les scans
 * porteurs d'une charge ; la faire toutes les quinze secondes coûterait une requête
 * inutile à chaque fois pour un résultat qui ne change qu'au rythme des scans.
 *
 * **Sans élection de meneur, et c'est délibéré ici.** La purge est idempotente :
 * abandonner deux fois la même charge ne coûte rien, et deux instances qui la lancent
 * ensemble aboutissent au même état. Ce n'est pas vrai de tous les travaux périodiques —
 * l'ordonnancement des scans, lui, exige une élection — donc ce service ne doit accueillir
 * que ce qui supporte d'être exécuté en double.
 */
@Injectable()
export class MaintenanceService {
    private readonly logger = new Logger(MaintenanceService.name);
    private busy = false;

    constructor(private readonly retention: RetentionService) {}

    @Cron(CronExpression.EVERY_HOUR)
    async pruneRawPayloads(): Promise<void> {
        // Le même garde que le travailleur de scan : une purge lente sur une base longtemps
        // négligée ne doit pas voir le tour suivant démarrer par-dessus.
        if (this.busy) return;
        this.busy = true;

        try {
            const result = await this.retention.prune();
            if (result.scansPruned > 0) this.logger.log(`Entretien : ${result.scansPruned} scan(s) allégé(s).`);
        } catch (error) {
            // Journalisé et avalé : un échec d'entretien ne doit pas faire tomber le
            // processus qui sert les requêtes.
            this.logger.error(`Purge de rétention échouée : ${(error as Error).message}`);
        } finally {
            this.busy = false;
        }
    }
}
