import Docker from 'dockerode';
import { PassThrough } from 'node:stream';

/**
 * L'exécution d'un conteneur de scanner.
 *
 * **Ces conteneurs analysent de l'entrée hostile par définition** — les métadonnées d'une
 * image que personne ne contrôle, un dépôt écrit par quelqu'un d'autre — et l'étape SBOM
 * d'image tourne avec la socket Docker montée, ce qui équivaut à root sur l'hôte. Les
 * limites ci-dessous ne suppriment pas ce risque ; elles retirent les escalades bon
 * marché : aucun nouveau privilège, aucune capacité, un plafond mémoire au lieu d'un OOM
 * sur l'hôte, un plafond de processus au lieu d'une bombe à fourche.
 *
 * **Les deux flux sont séparés.** Une seule sortie combinée corromprait le JSON de
 * stdout, et les taire toutes deux perdrait l'explication du scanner — celle qui finit
 * dans l'erreur affichée à l'opérateur. Chaque flux est donc lu séparément : stdout reste
 * analysable *et* la raison de l'échec survit.
 *
 * **Le réseau est coupé sauf là où l'outil a réellement quelque chose à chercher.** Grype
 * a besoin de sa base de vulnérabilités et Syft du registre ; gitleaks, checkov et un SBOM
 * de répertoire n'en ont jamais besoin.
 */

/** Plafond mémoire d'un conteneur de scan. Un dépassement tue le conteneur, pas l'hôte. */
export const MEMORY_LIMIT_BYTES = Number(process.env.ZANSHIN_SCAN_MEMORY_LIMIT_MB ?? 2048) * 1024 * 1024;

/** Plafond de processus : ce qui transforme une bombe à fourche en un conteneur mort. */
export const PIDS_LIMIT = Number(process.env.ZANSHIN_SCAN_PIDS_LIMIT ?? 512);

export const DEFAULT_TIMEOUT_MS = Number(process.env.ZANSHIN_SCAN_TIMEOUT_SECONDS ?? 900) * 1000;

export class ScannerTimeoutError extends Error {
    constructor(readonly label: string, readonly timeoutMs: number) {
        super(`Le scanner « ${label} » a dépassé ${Math.round(timeoutMs / 1000)} s et a été arrêté.`);
    }
}

export class ScannerExecutionError extends Error {
    constructor(
        readonly label: string,
        readonly exitCode: number,
        readonly stderr: string
    ) {
        // La sortie du scanner est incluse : sans elle, l'opérateur lit « le scanner a
        // échoué » et doit deviner. Tronquée, parce qu'un checkov bavard produit des
        // milliers de lignes dont seules les premières portent la cause.
        super(`Le scanner « ${label} » s'est arrêté en ${exitCode}. ${stderr.trim().slice(0, 2000)}`);
    }
}

export interface ContainerRun {
    image: string;
    command: string[];
    /** Montages hôte → conteneur. Le mode est explicite : « ro » partout où c'est possible. */
    binds: { source: string; target: string; readOnly?: boolean }[];
    label: string;
    /** Le réseau reste coupé par défaut. L'ouvrir doit être un geste conscient. */
    network?: boolean;
    /**
     * Faire tourner le conteneur en root.
     *
     * Nécessaire pour les images récentes qui tournent en utilisateur non privilégié : le
     * répertoire de travail est un `mkdtemp` en 0700 appartenant à l'utilisateur de
     * Zanshin, qu'un processus non root ne lit pas. `cap_drop: ALL` et
     * `no-new-privileges` continuent de s'appliquer.
     */
    asRoot?: boolean;
    timeoutMs?: number;
    /** Monter la socket Docker. **Équivaut à root sur l'hôte** — réservé au SBOM d'image. */
    dockerSocket?: boolean;
}

export interface ContainerResult {
    stdout: string;
    stderr: string;
    exitCode: number;
}

/** La marque posée sur chaque conteneur lancé par Zanshin. */
export const SCANNER_LABEL = 'dev.zanshin.scanner';

export class ContainerRunner {
    constructor(private readonly docker = new Docker()) {}

    /** Le démon est-il joignable ? Vérifié avant de réclamer un scan plutôt qu'au milieu. */
    async isAvailable(): Promise<boolean> {
        try {
            await this.docker.ping();
            return true;
        } catch {
            return false;
        }
    }

    async run(request: ContainerRun): Promise<ContainerResult> {
        const timeoutMs = request.timeoutMs ?? DEFAULT_TIMEOUT_MS;
        const binds = request.binds.map(({ source, target, readOnly }) => `${source}:${target}${readOnly ? ':ro' : ''}`);
        if (request.dockerSocket) binds.push('/var/run/docker.sock:/var/run/docker.sock');

        const container = await this.docker.createContainer({
            Image: request.image,
            Cmd: request.command,
            ...(request.asRoot ? { User: '0:0' } : {}),
            // **Étiqueté, parce que la machine qui scanne n'est pas forcément à nous.** Un
            // agent tourne sur un hôte partagé, où d'autres conteneurs vont et viennent :
            // sans marque, ni un opérateur ni un balayage d'orphelins ne peut distinguer
            // ce que Zanshin a lancé du reste.
            Labels: { [SCANNER_LABEL]: request.label },
            HostConfig: {
                Binds: binds,
                NetworkMode: request.network ? 'bridge' : 'none',
                Memory: MEMORY_LIMIT_BYTES,
                PidsLimit: PIDS_LIMIT,
                CapDrop: ['ALL'],
                SecurityOpt: ['no-new-privileges'],
                // Supprimé par le démon à l'arrêt : un scan interrompu ne doit pas laisser
                // s'accumuler des conteneurs morts sur la machine qui scanne.
                AutoRemove: false
            }
        });

        const stdout = new PassThrough();
        const stderr = new PassThrough();
        const outChunks: Buffer[] = [];
        const errChunks: Buffer[] = [];
        stdout.on('data', (chunk: Buffer) => outChunks.push(chunk));
        stderr.on('data', (chunk: Buffer) => errChunks.push(chunk));

        try {
            const stream = await container.attach({ stream: true, stdout: true, stderr: true });
            // Le protocole Docker multiplexe les deux flux sur une seule connexion ;
            // `demuxStream` les sépare. Sans cela, le JSON de stdout serait entrelacé avec
            // les avertissements du scanner et deviendrait illisible.
            container.modem.demuxStream(stream, stdout, stderr);

            await container.start();
            const exitCode = await this.waitWithTimeout(container, timeoutMs, request.label);

            // Laisser les flux se vider : `wait` rend la main avant que le dernier bloc
            // n'ait traversé, et un JSON tronqué se lit comme un JSON invalide.
            await new Promise((resolve) => setTimeout(resolve, 50));

            return {
                stdout: Buffer.concat(outChunks).toString('utf8'),
                stderr: Buffer.concat(errChunks).toString('utf8'),
                exitCode
            };
        } finally {
            // Dans un `finally` : un conteneur oublié retient son espace de travail, donc
            // le clone entier, et la machine finit par manquer de disque.
            await container.remove({ force: true }).catch(() => undefined);
        }
    }

    /**
     * Attend la fin, ou arrête le conteneur.
     *
     * L'arrêt est nécessaire et non optionnel : abandonner l'attente laisserait le
     * conteneur tourner indéfiniment, consommant sa mémoire et ses processus, pendant que
     * Zanshin considère le scan terminé.
     */
    private async waitWithTimeout(container: Docker.Container, timeoutMs: number, label: string): Promise<number> {
        let timer: NodeJS.Timeout | undefined;
        const expiry = new Promise<never>((_, reject) => {
            timer = setTimeout(() => reject(new ScannerTimeoutError(label, timeoutMs)), timeoutMs);
        });

        try {
            const result = (await Promise.race([container.wait(), expiry])) as { StatusCode?: number };
            return result.StatusCode ?? 0;
        } catch (error) {
            if (error instanceof ScannerTimeoutError) {
                await container.stop({ t: 5 }).catch(() => undefined);
            }
            throw error;
        } finally {
            if (timer) clearTimeout(timer);
        }
    }
}

/**
 * Lit la sortie JSON d'un scanner, ou explique pourquoi elle est inutilisable.
 *
 * **Rend `null` et jamais `[]` en cas d'échec.** La distinction est celle entre « analysé,
 * rien trouvé » et « pas analysé », et elle décide du sort de tout le backlog du type
 * concerné : une liste vide fait résoudre chaque problème existant, un `null` ne fait
 * rien. C'est la même règle que pour `scannedTypes`.
 */
export function parseScannerJson<T>(result: ContainerResult, label: string, acceptedExitCodes: number[] = [0]): T | null {
    if (!acceptedExitCodes.includes(result.exitCode)) {
        throw new ScannerExecutionError(label, result.exitCode, result.stderr);
    }
    const payload = result.stdout.trim();
    if (!payload) return null;
    try {
        return JSON.parse(payload) as T;
    } catch {
        return null;
    }
}
