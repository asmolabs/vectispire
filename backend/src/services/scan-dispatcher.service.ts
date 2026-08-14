import { Injectable, Logger } from '@nestjs/common';
import { DataSource, EntityManager } from 'typeorm';
import { privateKeyContext } from '../domain/crypto/encryption';
import { now } from '../domain/common/timestamp';
import { capacity } from '../domain/scans/queue-rules';
import { Agent, Container, Repository as GitRepository, Scan, SshKey, STATUS_COMPLETED, STATUS_FAILED, STATUS_QUEUED } from '../persistence/entities';
import { ScanRepository } from '../repositories/scan.repository';
import { formatImageReference } from '../domain/targets/image-reference';
import { ScanRunner, type ScanArtifacts } from '../scanning/scan-runner';
import { SETTING_SAST_ENABLED } from '../domain/settings/keys';
import { EncryptionService } from './encryption.service';
import { ScanIngestorService } from './scan-ingestor.service';
import { SettingsService } from './settings.service';

/** Levée quand une clé de déploiement partirait en clair. Sa propre classe, pour que
 *  l'API la traduise en 412 et non en 500. */
export class InsecureCredentialTransport extends Error {
    constructor() {
        super("Cet agent reçoit les clés de déploiement, ce qui exige une liaison chiffrée.");
    }
}

/** Ce qu'un agent reçoit : la tâche, plus l'identifiant du scan qu'il devra rendre. */
export type AgentTask = Awaited<ReturnType<ScanDispatcherService['buildTaskPublic']>> & { scanId: number };

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
        private readonly encryption: EncryptionService = new EncryptionService(),
        /** Facultatif : les tests de file n'ont pas de réglages, et sans lui le SAST reste
         *  désactivé — le comportement le plus prudent des deux. */
        private readonly settings: SettingsService | null = null
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

    /**
     * Remet une tâche à un agent distant, ou rend `null` s'il n'y a rien à faire.
     *
     * **La clé de déploiement ne part que si la liaison est chiffrée.** Un agent en mode
     * `delegated` reçoit la clé privée du dépôt ; l'envoyer en clair la donnerait à qui
     * écoute le réseau. Le scan est alors remis en file plutôt que confié.
     */
    async claimForAgent(agent: Agent, secureTransport: boolean, waitSeconds: number): Promise<AgentTask | null> {
        const deadline = Date.now() + waitSeconds * 1000;

        do {
            const claimed = await this.dataSource.transaction((manager) => this.scans.claim(manager, 1, agent.id));
            if (claimed.length > 0) {
                const scan = claimed[0];
                try {
                    const task = await this.dataSource.transaction((manager) => this.buildTask(manager, scan));
                    if (task.privateKey && !secureTransport) {
                        // Remis en file avant de refuser : sans cela le scan resterait
                        // réclamé par un agent qui n'a rien reçu, jusqu'à expiration.
                        await this.dataSource.transaction((manager) =>
                            manager.update(Scan, { id: scan.id }, { status: STATUS_QUEUED, claimedBy: null, claimedAt: null, leaseExpiresAt: null })
                        );
                        throw new InsecureCredentialTransport();
                    }
                    return { scanId: scan.id, ...task };
                } catch (error) {
                    if (error instanceof InsecureCredentialTransport) throw error;
                    await this.finishAsFailed(scan, (error as Error).message);
                    return null;
                }
            }

            // Attente courte plutôt qu'une seule vérification : un agent qui interroge
            // toutes les trente secondes verrait sinon un scan attendre presque autant.
            if (Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 1000));
        } while (Date.now() < deadline);

        return null;
    }

    /** Prolonge le bail d'un scan confié à cet agent. */
    async renewAgentLease(scanId: number, agent: Agent): Promise<boolean> {
        return this.dataSource.transaction((manager) => this.scans.renewLease(manager, scanId, agent.id));
    }

    /**
     * Accepte le résultat d'un scan exécuté ailleurs.
     *
     * Rend `false` si le bail a été repris entre-temps : les résultats sont alors écartés
     * plutôt qu'écrits, pour ne pas écraser le travail du successeur.
     */
    async acceptAgentResult(scanId: number, agent: Agent, payload: Record<string, unknown>): Promise<boolean> {
        const artifacts: ScanArtifacts = {
            // `?? null` et non `?? []` : un agent qui n'a pas exécuté une étape doit laisser
            // le backlog de ce type intact, et l'absence de champ le dit.
            sbom: (payload.sbom as ScanArtifacts['sbom']) ?? null,
            dependencies: (payload.dependencies as ScanArtifacts['dependencies']) ?? null,
            secrets: (payload.secrets as ScanArtifacts['secrets']) ?? null,
            iac: (payload.iac as ScanArtifacts['iac']) ?? null,
            sast: (payload.sast as ScanArtifacts['sast']) ?? null,
            failures: (payload.failures as ScanArtifacts['failures']) ?? [],
            durationMs: Number(payload.duration_ms ?? 0)
        };

        let accepted = false;
        await this.dataSource.transaction(async (manager) => {
            if (!(await this.scans.stillOwned(manager, scanId, agent.id))) return;

            const scan = await manager.findOneByOrFail(Scan, { id: scanId });
            const result = await this.ingestor.ingest(manager, scan, artifacts);
            Object.assign(scan, {
                status: STATUS_COMPLETED,
                findingsCount: result.new + result.reopened + result.stillOpen,
                newIssuesCount: result.new,
                resolvedIssuesCount: result.resolved,
                durationMs: artifacts.durationMs,
                sbom: artifacts.sbom,
                error: artifacts.failures.length ? artifacts.failures.map((f) => `${f.step} : ${f.reason}`).join(' | ').slice(0, 2000) : null,
                claimedBy: null,
                claimedAt: null,
                leaseExpiresAt: null
            });
            await manager.save(Scan, scan);
            accepted = true;
        });
        return accepted;
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
    /** Exposée pour le typage de `AgentTask` uniquement. */
    async buildTaskPublic(manager: EntityManager, scan: Scan) {
        return this.buildTask(manager, scan);
    }

    /**
     * La tâche d'un scan d'image.
     *
     * **Aucune clé n'est envoyée**, quel que soit le mode de l'agent : une image se tire
     * d'un registre, pas d'un dépôt git, et les identifiants de registre relèvent de la
     * configuration Docker de la machine qui scanne. C'est ce qui rend le scan d'image
     * distribuable sans la précaution de liaison chiffrée qu'exige une clé de déploiement.
     */
    private async buildImageTask(manager: EntityManager, scan: Scan) {
        if (scan.containerId === null) {
            throw new Error('Ce scan ne porte ni dépôt ni conteneur : il ne désigne aucune cible.');
        }
        const container = await manager.findOneByOrFail(Container, { id: scan.containerId });

        return {
            image: formatImageReference(container),
            // Lue de l'environnement du plan de contrôle et non de l'agent : c'est une
            // décision sur *ce qu'on veut scanner* — l'image qui tourne en production —
            // et non sur la machine qui l'exécute.
            platform: process.env.ZANSHIN_IMAGE_SCAN_PLATFORM ?? null,
            // Le coureur bascule sur `image` ; ces champs ne sont pas lus sur ce chemin,
            // mais le type les exige et les laisser vides serait moins clair qu'un aveu.
            url: '',
            branch: 'n/a',
            subPath: '',
            privateKey: null,
            runDependencies: true,
            runSecrets: false,
            runIac: false,
            runSast: false
        };
    }

    private async buildTask(manager: EntityManager, scan: Scan) {
        if (scan.repoId === null) return this.buildImageTask(manager, scan);

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
            image: null,
            platform: null,
            url: repository.url,
            branch: scan.branch || repository.branch,
            subPath: repository.subPath ?? '',
            privateKey,
            runDependencies: true,
            runSecrets: true,
            runIac: true,
            // **Lu ici et posé sur la tâche**, jamais lu par le travailleur : un agent
            // distant n'a pas de base. Codé en dur à `false` jusqu'ici, ce qui rendait
            // toute la chaîne SAST — scanner, règles, ingestion, écran Qualité —
            // inatteignable sans qu'aucun test ne s'en aperçoive.
            runSast: this.settings ? await this.settings.isEnabled(SETTING_SAST_ENABLED, false) : false
        };
    }
}
