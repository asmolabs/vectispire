import type { AgentProtocol, AssignedTask } from './protocol';
import type { ScanArtifacts, ScanTask } from '../scanning/scan-runner';

/**
 * La boucle d'un agent distant : réclamer, exécuter, rendre.
 *
 * Séparée du protocole et du coureur pour la même raison qu'ailleurs dans ce dépôt :
 * ce fichier porte des **décisions** — quand renoncer, quand se taire, que faire d'un bail
 * perdu — et elles se testent sans réseau ni Docker.
 */

/** Ce qui exécute réellement les scanners. `ScanRunner.run` en production. */
export type Execute = (task: ScanTask) => Promise<ScanArtifacts>;

export interface LoopOptions {
    /** L'attente longue demandée au serveur à chaque réclamation. */
    waitSeconds: number;
    /** Le délai après une panne de réseau, avant de réessayer. */
    retryDelayMs: number;
    /**
     * L'intervalle entre deux signes de vie pendant un scan.
     *
     * **Périodique et non lié aux étapes du scanner.** Un battement envoyé à chaque étape
     * se tairait pendant les quinze minutes que Semgrep peut prendre sur un gros dépôt, et
     * le bail expirerait alors qu'il progresse. Un battement dit « je suis vivant et je
     * travaille sur ce scan » — c'est une horloge qui l'exprime fidèlement, pas un
     * découpage du travail.
     */
    heartbeatMs: number;
    /** Rendu par le sommeil, pour que les tests n'attendent pas. */
    sleep: (ms: number) => Promise<void>;
    log: (message: string) => void;
    warn: (message: string) => void;
}

export interface LoopResult {
    completed: number;
    failed: number;
    abandoned: number;
}

/**
 * Un tour : au plus un scan.
 *
 * **Un seul à la fois, même quand le plan de contrôle en autorise plusieurs.** La
 * concurrence est décidée par le nombre de processus d'agent qu'un opérateur lance, pas
 * par ce fichier : lancer trois scans de front sur une machine qui n'en supporte qu'un les
 * ferait tous expirer plutôt qu'un seul réussir, et c'est le genre de réglage qui doit se
 * voir dans un `docker compose` plutôt que se deviner dans du code.
 */
export async function runOnce(protocol: AgentProtocol, execute: Execute, options: LoopOptions): Promise<LoopResult> {
    const empty: LoopResult = { completed: 0, failed: 0, abandoned: 0 };

    let task: AssignedTask | null;
    try {
        task = await protocol.claim(options.waitSeconds);
    } catch (error) {
        // Une panne de réclamation n'est pas un scan perdu : le plan de contrôle garde la
        // ligne en file, et un autre agent — ou celui-ci au tour suivant — la prendra.
        options.warn(`Réclamation impossible : ${(error as Error).message}`);
        await options.sleep(options.retryDelayMs);
        return empty;
    }

    if (task === null) return empty;

    options.log(`Scan ${task.scanId} : ${task.url} (${task.branch}).`);
    let artifacts: ScanArtifacts;
    let lost = false;

    // **Le signe de vie tourne pendant l'exécution.** C'est ce qui distingue « long » de
    // « mort » : sans lui, un scan de vingt minutes verrait son bail expirer et serait
    // repris par un autre, qui referait le même travail pendant que le premier le termine.
    const beating = setInterval(() => {
        void protocol
            .heartbeat(task!.scanId)
            .then((held) => {
                if (!held) lost = true;
            })
            // Un battement perdu n'est pas un bail perdu : le réseau hoquette, et le bail
            // dure plusieurs fois l'intervalle. Marquer `lost` ici abandonnerait un scan
            // valide sur un incident passager.
            .catch((error: Error) => options.warn(`Signe de vie manqué pour le scan ${task!.scanId} : ${error.message}`));
    }, options.heartbeatMs);

    try {
        artifacts = await execute(task);
    } catch (error) {
        // **Rien n'est rendu.** Un agent qui poste un résultat vide après un échec
        // d'exécution ferait résoudre en silence tout le backlog des types qu'il n'a pas
        // regardés — `null` contre `[]`, la distinction que tout ce système protège. Le
        // bail expire, le scan repart en file, et un autre agent le reprend.
        options.warn(`Scan ${task.scanId} abandonné : ${(error as Error).message}`);
        return { ...empty, failed: 1 };
    } finally {
        clearInterval(beating);
    }

    if (lost) {
        // Le bail a été repris pendant le travail. Rendre le résultat écraserait celui du
        // successeur, qui est plus récent que le nôtre.
        options.warn(`Scan ${task.scanId} : bail repris pendant l'exécution, résultat écarté.`);
        return { ...empty, abandoned: 1 };
    }

    try {
        if (await protocol.submit(task.scanId, artifacts)) {
            options.log(`Scan ${task.scanId} rendu.`);
            return { ...empty, completed: 1 };
        }
        options.warn(`Scan ${task.scanId} : résultat écarté, le bail ne nous appartenait plus.`);
        return { ...empty, abandoned: 1 };
    } catch (error) {
        // Le travail est fait mais n'a pas pu être rendu. C'est le cas le plus frustrant,
        // et le plus honnête à traiter ainsi : réessayer l'envoi tiendrait un agent occupé
        // sur un résultat dont le bail expire de toute façon.
        options.warn(`Scan ${task.scanId} : résultat non transmis (${(error as Error).message}).`);
        return { ...empty, failed: 1 };
    }
}
