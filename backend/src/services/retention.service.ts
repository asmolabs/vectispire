import { Injectable, Logger } from '@nestjs/common';
import { InjectEntityManager } from '@nestjs/typeorm';
import { EntityManager, In, IsNull, Not } from 'typeorm';
import { now } from '../domain/common/timestamp';
import {
    DEFAULT_KEEP_PER_TARGET,
    DEFAULT_MAX_AGE_DAYS,
    type RetentionPolicy,
    SETTING_RETENTION_KEEP_PER_TARGET,
    SETTING_RETENTION_MAX_AGE_DAYS,
    intSetting,
    isEnabled,
    prunable
} from '../domain/retention/policy';
import { Scan } from '../persistence/entities';
import { SettingsService } from './settings.service';

export interface PruneResult {
    scansPruned: number;
}

/**
 * La purge des charges brutes de scanner.
 *
 * **Ce que cette version ne fait plus, et pourquoi.** La version Python lançait un `VACUUM`
 * après chaque purge, parce que SQLite garde ses pages vidées et que sans lui le fichier ne
 * rétrécissait jamais — l'opérateur ne voyait aucun effet. PostgreSQL et MySQL réutilisent
 * l'espace d'eux-mêmes, et un `VACUUM FULL` prendrait un verrou exclusif sur la table le
 * temps de la réécrire : le remède serait pire que le mal. L'espace est donc rendu au
 * moteur, pas au système de fichiers, et c'est le comportement correct ici.
 *
 * **Idempotent, donc sûr sans élection.** Abandonner deux fois la même charge ne coûte
 * rien. C'est ce qui permet à la purge de tourner dans chaque instance avant que
 * l'élection de meneur ne soit portée, sans risque d'incohérence.
 */
@Injectable()
export class RetentionService {
    private readonly logger = new Logger(RetentionService.name);

    constructor(
        @InjectEntityManager() private readonly manager: EntityManager,
        private readonly settings: SettingsService
    ) {}

    async policy(): Promise<RetentionPolicy> {
        const [keep, age] = await Promise.all([
            this.settings.get(SETTING_RETENTION_KEEP_PER_TARGET, ''),
            this.settings.get(SETTING_RETENTION_MAX_AGE_DAYS, '')
        ]);
        return {
            keepPerTarget: intSetting(keep, DEFAULT_KEEP_PER_TARGET),
            maxAgeDays: intSetting(age, DEFAULT_MAX_AGE_DAYS)
        };
    }

    /** Les identifiants des scans dont les charges peuvent être abandonnées. */
    async findPrunable(manager: EntityManager = this.manager): Promise<number[]> {
        const policy = await this.policy();
        if (!isEnabled(policy)) return [];

        // **Seules les colonnes de décision sont lues.** Charger les entités entières
        // ramènerait les blocs eux-mêmes en mémoire — plusieurs mégaoctets par scan — pour
        // décider de les effacer, ce qui est exactement ce que la purge cherche à éviter.
        const candidates = await manager
            .createQueryBuilder(Scan, 'scan')
            .select(['scan.id', 'scan.repoId', 'scan.containerId', 'scan.createdAt'])
            .where('scan.sbom IS NOT NULL OR scan.cves IS NOT NULL')
            .orderBy('scan.createdAt', 'DESC')
            .addOrderBy('scan.id', 'DESC')
            .getMany();

        return prunable(candidates, policy, now());
    }

    /**
     * Abandonne les charges brutes de tous les scans purgeables.
     *
     * L'écriture passe par un `UPDATE` en masse et non par `save` : réhydrater chaque
     * entité pour lui poser deux `null` relirait les blocs qu'on veut justement ne plus
     * toucher.
     */
    async prune(manager: EntityManager = this.manager): Promise<PruneResult> {
        const ids = await this.findPrunable(manager);
        if (ids.length === 0) return { scansPruned: 0 };

        // Par tranches : une clause `IN` de plusieurs dizaines de milliers d'identifiants
        // dépasse les limites de paramètres de certains pilotes, et la purge d'une base
        // longtemps négligée est précisément le cas où la liste est longue.
        for (let index = 0; index < ids.length; index += 500) {
            // `() => 'NULL'` et non `null` : sur une colonne JSON, la valeur `null` de
            // TypeScript peut être sérialisée en littéral JSON `null`, qui satisfait
            // `IS NOT NULL`. La purge re-sélectionnerait alors les mêmes lignes à chaque
            // passage sans rien libérer, en rapportant un compte parfaitement crédible.
            await manager.update(Scan, { id: In(ids.slice(index, index + 500)) }, { sbom: () => 'NULL', cves: () => 'NULL' });
        }

        const policy = await this.policy();
        this.logger.log(
            `Rétention : charges brutes abandonnées pour ${ids.length} scan(s) ` +
                `(garde ${policy.keepPerTarget} par cible, âge maximal ${policy.maxAgeDays} jours).`
        );
        return { scansPruned: ids.length };
    }

    /** Combien de scans portent encore une charge brute — le chiffre que montre l'écran. */
    async payloadCount(manager: EntityManager = this.manager): Promise<number> {
        return manager.count(Scan, { where: [{ sbom: Not(IsNull()) }, { cves: Not(IsNull()) }] });
    }
}
