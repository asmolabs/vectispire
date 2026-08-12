import { Injectable, Logger } from '@nestjs/common';
import { DataSource, EntityManager } from 'typeorm';
import { privateKeyContext } from '../domain/crypto/encryption';
import { now } from '../domain/common/timestamp';
import { capacity } from '../domain/scans/queue-rules';
import { Repository as GitRepository, Scan, SshKey, STATUS_COMPLETED, STATUS_FAILED } from '../persistence/entities';
import { ScanRepository } from '../repositories/scan.repository';
import { ScanRunner, type ScanArtifacts } from '../scanning/scan-runner';
import { EncryptionService } from './encryption.service';
import { ScanIngestorService } from './scan-ingestor.service';

/**
 * Le distributeur : il réclame des scans, les fait exécuter, ingère leurs résultats et
 * rend les baux.
 *
 * **Chaque scan a sa propre transaction**, et non une transaction pour le tour entier :
 * un scan qui échoue ne doit pas annuler l'ingestion de celui qui a réussi juste avant.
 * C'est aussi ce qui permet de rendre un bail sans attendre la fin des autres.
 *
 * **La réclamation et l'exécution sont séparées.** La réclamation est courte et
 * transactionnelle ; l'exécution dure des minutes et ne doit surtout pas tenir une
 * transaction ouverte — elle bloquerait le nettoyage de PostgreSQL et transformerait la
 * moindre lenteur de scanner en incident de base.
 */
@Injectable()
export class ScanDispatcherService {
    private readonly logger = new Logger(ScanDispatcherService.name);

    constructor(
        private readonly dataSource: DataSource,
        private readonly scans: ScanRepository = new ScanRepository(),
        private readonly runner: ScanRunner = new ScanRunner(),
        private readonly ingestor: ScanIngestorService = new ScanIngestorService(),
        private readonly encryption: EncryptionService = new EncryptionService()
    ) {}

    /**
     * Un tour de distribution : reprend les baux perdus, puis réclame et exécute.
     *
     * `worker` identifie qui réclame. Il finit dans `claimedBy` et sert à `stillOwned` :
     * sans lui, un travailleur dont le bail a expiré écraserait le travail de son
     * successeur en rendant des résultats périmés.
     */
    async dispatch(worker: string, maxConcurrent: number): Promise<{ claimed: number; completed: number; failed: number }> {
        await this.reclaimLostLeases();

        const running = await this.dataSource.transaction((manager) => this.scans.countRunning(manager));
        const room = capacity(maxConcurrent, running);
        if (room === 0) return { claimed: 0, completed: 0, failed: 0 };

        const claimed = await this.dataSource.transaction((manager) => this.scans.claim(manager, room, worker));

        let completed = 0;
        let failed = 0;
        for (const scan of claimed) {
            // Séquentiel et non parallèle : la capacité a déjà été décidée par le nombre
            // réclamé, et lancer cinq scans de front sur une machine qui n'en supporte
            // qu'un les ferait tous expirer plutôt qu'un seul réussir.
            (await this.execute(scan, worker)) ? (completed += 1) : (failed += 1);
        }
        return { claimed: claimed.length, completed, failed };
    }

    private async reclaimLostLeases(): Promise<void> {
        const { requeued, failed } = await this.dataSource.transaction((manager) => this.scans.reclaimExpiredLeases(manager));
        if (requeued.length) this.logger.warn(`${requeued.length} scan(s) abandonné(s) remis en file.`);
        if (failed.length) this.logger.error(`${failed.length} scan(s) en échec définitif après trop de reprises.`);
    }

    /** Rend `true` si le scan s'est terminé normalement. */
    private async execute(scan: Scan, worker: string): Promise<boolean> {
        let artifacts: ScanArtifacts;
        try {
            const task = await this.dataSource.transaction((manager) => this.buildTask(manager, scan));
            // **Hors transaction, délibérément.** L'exécution dure des minutes ; tenir une
            // transaction ouverte pendant ce temps bloquerait le nettoyage de PostgreSQL.
            artifacts = await this.runner.run(task);
        } catch (error) {
            await this.finishAsFailed(scan, (error as Error).message);
            return false;
        }

        try {
            await this.dataSource.transaction(async (manager) => {
                // Le bail est vérifié **dans la transaction d'écriture** : entre la fin de
                // l'exécution et maintenant, un autre travailleur a pu reprendre ce scan,
                // et écrire ici écraserait son travail avec des résultats périmés.
                if (!(await this.scans.stillOwned(manager, scan.id, worker))) {
                    this.logger.warn(`Scan ${scan.id} repris par un autre travailleur pendant son exécution — résultats écartés.`);
                    return;
                }

                const fresh = await manager.findOneByOrFail(Scan, { id: scan.id });
                const result = await this.ingestor.ingest(manager, fresh, artifacts);

                Object.assign(fresh, {
                    status: STATUS_COMPLETED,
                    findingsCount: result.new + result.reopened + result.stillOpen,
                    newIssuesCount: result.new,
                    resolvedIssuesCount: result.resolved,
                    durationMs: artifacts.durationMs,
                    sbom: artifacts.sbom,
                    // Les échecs d'étape sont consignés même sur un scan réussi : sans
                    // cela, l'opérateur ne saurait pas qu'un scanner n'a rien regardé.
                    error: artifacts.failures.length ? artifacts.failures.map((f) => `${f.step} : ${f.reason}`).join(' | ').slice(0, 2000) : null,
                    claimedBy: null,
                    claimedAt: null,
                    leaseExpiresAt: null
                });
                await manager.save(Scan, fresh);
            });
            return true;
        } catch (error) {
            await this.finishAsFailed(scan, (error as Error).message);
            return false;
        }
    }

    /**
     * Marque le scan en échec et **rend son bail**.
     *
     * Le bail doit tomber ici : un scan en échec qui garderait le sien serait repris par
     * la reprise suivante, et échouerait à nouveau, jusqu'à épuisement des tentatives.
     */
    private async finishAsFailed(scan: Scan, reason: string): Promise<void> {
        await this.dataSource.transaction(async (manager) => {
            await manager.update(
                Scan,
                { id: scan.id },
                { status: STATUS_FAILED, error: reason.slice(0, 2000), claimedBy: null, claimedAt: null, leaseExpiresAt: null }
            );
        });
    }

    /**
     * Prépare la tâche : c'est ici que la clé privée est déchiffrée, et **seulement ici**.
     *
     * Le coureur reçoit la clé en clair parce qu'il doit la donner à git, mais il ne
     * connaît ni la base ni la clé de chiffrement — c'est ce qui permet à un agent distant
     * d'exécuter le même code sans jamais approcher le secret d'un autre dépôt.
     */
    private async buildTask(manager: EntityManager, scan: Scan) {
        if (scan.repoId === null) {
            throw new Error("Ce scan ne porte pas de dépôt : le scan d'image n'est pas encore distribué par ce chemin.");
        }
        const repository = await manager.findOneByOrFail(GitRepository, { id: scan.repoId });

        let privateKey: string | null = null;
        if (repository.sshKeyId) {
            const key = await manager.findOneBy(SshKey, { id: repository.sshKeyId });
            if (!key) throw new Error(`La clé SSH du dépôt ${repository.url} a été supprimée.`);
            const secret = this.encryption.inspect(key.privateKey, privateKeyContext(key.id));
            if (secret.state === 'unreadable') {
                // Message explicite : sans lui, l'échec ressemblerait à un refus du serveur
                // git, et l'opérateur chercherait du côté du fournisseur.
                throw new Error(`La clé SSH « ${key.name} » n'est déchiffrable par aucune clé de chiffrement configurée.`);
            }
            privateKey = secret.plainText;
        }

        return {
            url: repository.url,
            branch: scan.branch || repository.branch,
            subPath: repository.subPath ?? '',
            privateKey,
            runDependencies: true,
            runSecrets: true,
            runIac: true,
            runSast: false
        };
    }
}
