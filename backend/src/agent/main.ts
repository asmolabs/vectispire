import { hostname, platform, release } from 'node:os';
import { CONTRACT_VERSION } from '../domain/agents/contract';
import { generateEphemeralKeyPair } from '../domain/crypto/sealed-envelope';
import { ScanRunner } from '../scanning/scan-runner';
import { runOnce } from './agent-loop';
import { AgentProtocol, ContractMismatch, type HttpCall, Unauthorized } from './protocol';

/**
 * L'agent distant : un processus qui exécute des scans pour un Zanshin qu'il ne connaît
 * que par HTTP.
 *
 * ```bash
 * ZANSHIN_URL=https://zanshin.interne \
 * ZANSHIN_AGENT_TOKEN=zsk_... \
 * node dist/agent/main.js
 * ```
 *
 * **Il n'a aucun accès à la base**, et c'est ce qui justifie son existence : sortir le
 * socket Docker de la machine qui sert l'interface, atteindre un dépôt qui n'est routable
 * que depuis un autre segment, ou ajouter de la capacité — sans donner au passage de quoi
 * déchiffrer les clés de déploiement.
 *
 * **Il partage `ScanRunner` avec le travailleur intégré.** Un résultat produit ici est donc
 * indiscernable d'un résultat local : mêmes constats, même enrichissement, même
 * réconciliation. Un second chemin d'exécution aurait divergé au premier scanner ajouté.
 */

const DEFAULT_WAIT_SECONDS = 30;
const DEFAULT_RETRY_MS = 10_000;
const DEFAULT_HEARTBEAT_MS = 60_000;

export async function main(): Promise<void> {
    const baseUrl = (process.env.ZANSHIN_URL ?? '').trim().replace(/\/+$/, '');
    const token = (process.env.ZANSHIN_AGENT_TOKEN ?? '').trim();

    // Refus immédiat et nommé. Un agent qui démarre sans configuration et boucle sur des
    // 401 se lit comme un problème de réseau, et l'opérateur cherche du mauvais côté.
    if (!baseUrl) throw new Error("ZANSHIN_URL est requis : l'URL du plan de contrôle.");
    if (!token) throw new Error("ZANSHIN_AGENT_TOKEN est requis : la clé d'API affichée une seule fois à la création de l'agent.");

    if (!baseUrl.startsWith('https://')) {
        // Averti et non refusé : un agent en mode `local` ne reçoit aucune clé, et un
        // déploiement derrière un proxy inverse voit du HTTP légitimement. Le plan de
        // contrôle, lui, refuse de déléguer une clé en clair sur une liaison en clair —
        // c'est là que la décision a du sens, parce qu'il sait ce qu'il enverrait. Une clé
        // scellée, elle, ne voyage jamais en clair : l'exigence tombe d'elle-même.
        console.warn(`Liaison non chiffrée vers ${baseUrl} : seules des clés scellées y seront déléguées.`);
    }

    // **Régénérée à chaque démarrage, jamais écrite.** Un agent redémarré est un nouveau
    // destinataire ; il n'y a aucun fichier de clé à protéger, tourner ou oublier, et rien
    // à récupérer sur le disque d'une machine de scan compromise.
    const keyPair = generateEphemeralKeyPair();

    const protocol = new AgentProtocol(httpCall(baseUrl, token), keyPair);
    const identity = await protocol.hello({
        hostname: hostname(),
        platform: `${platform()} ${release()}`,
        version: process.env.ZANSHIN_VERSION ?? CONTRACT_VERSION,
        scannerEngine: 'docker'
    });

    console.log(`Agent « ${identity.name} » annoncé — contrat ${identity.contractVersion}, identifiants ${identity.credentialsMode}.`);

    const runner = new ScanRunner();
    const options = {
        waitSeconds: boundedInt(process.env.ZANSHIN_AGENT_WAIT_SECONDS, DEFAULT_WAIT_SECONDS, 1, 300),
        retryDelayMs: boundedInt(process.env.ZANSHIN_AGENT_RETRY_MS, DEFAULT_RETRY_MS, 1_000, 300_000),
        // Bien plus court que le bail (900 s) : un battement manqué ne doit pas suffire à
        // faire expirer un scan qui progresse.
        heartbeatMs: boundedInt(process.env.ZANSHIN_AGENT_HEARTBEAT_MS, DEFAULT_HEARTBEAT_MS, 5_000, 600_000),
        sleep: (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)),
        log: (message: string) => console.log(message),
        warn: (message: string) => console.warn(message)
    };

    let stopping = false;
    // **Arrêt propre.** Le scan en cours va jusqu'au bout : le tuer laisserait un bail
    // couru jusqu'à expiration, et le travail déjà fait serait perdu pour rien.
    for (const signal of ['SIGINT', 'SIGTERM'] as const) {
        process.on(signal, () => {
            if (stopping) process.exit(1);
            stopping = true;
            console.log(`${signal} reçu : arrêt après le scan en cours.`);
        });
    }

    while (!stopping) {
        try {
            await runOnce(protocol, (task) => runner.run(task), options);
        } catch (error) {
            if (error instanceof Unauthorized || error instanceof ContractMismatch) throw error;
            // Tout le reste est transitoire par hypothèse : le plan de contrôle qui
            // redémarre, le réseau qui hoquette. Boucler est le bon comportement, se taire
            // ne l'est pas.
            console.warn(`Tour d'agent échoué : ${(error as Error).message}`);
            await options.sleep(options.retryDelayMs);
        }
    }
    console.log('Agent arrêté.');
}

/**
 * L'appel HTTP, avec la clé sur chaque requête.
 *
 * Le corps n'est lu qu'en cas d'erreur ou de réponse attendue : un 204 n'en a pas, et le
 * parser produirait une exception là où il n'y a rien à lire.
 */
function httpCall(baseUrl: string, token: string): HttpCall {
    return async (path, init) => {
        const response = await fetch(`${baseUrl}${path}`, {
            method: init.method,
            headers: {
                Authorization: `Bearer ${token}`,
                ...(init.body === undefined ? {} : { 'content-type': 'application/json' })
            },
            body: init.body === undefined ? undefined : JSON.stringify(init.body),
            // **Refusées, comme partout ailleurs.** Le plan de contrôle est une adresse fixe
            // de configuration : il n'a aucune raison de rediriger, et suivre une redirection
            // enverrait les résultats d'un scan — voire la réclamation qui porte la clé
            // d'API — vers un hôte que personne n'a déclaré. Un proxy qui redirige HTTP vers
            // HTTPS fait alors échouer l'agent bruyamment, ce qui est le bon résultat : le
            // correctif est de poser `ZANSHIN_URL` en https.
            redirect: 'error',
            signal: AbortSignal.timeout(init.timeoutMs)
        });

        if (response.status === 204) return { status: 204, body: null };

        const text = await response.text();
        let body: unknown = null;
        try {
            body = text ? JSON.parse(text) : null;
        } catch {
            // Une réponse illisible est une information : un proxy qui rend du HTML, par
            // exemple. Le texte brut vaut mieux qu'une exception de parsing.
            body = { message: text.slice(0, 500) };
        }
        return { status: response.status, body };
    };
}

function boundedInt(raw: string | undefined, fallback: number, min: number, max: number): number {
    const value = Number(raw);
    if (!Number.isInteger(value)) return fallback;
    return Math.min(Math.max(value, min), max);
}

// Exécuté seulement quand ce fichier *est* le programme : l'importer depuis un test ne
// doit pas démarrer une boucle infinie.
if (require.main === module) {
    main().catch((error: Error) => {
        console.error(error.message);
        process.exit(1);
    });
}
