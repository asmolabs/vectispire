import { CONTRACT_VERSION } from '../domain/agents/contract';
import type { ScanArtifacts, ScanTask } from '../scanning/scan-runner';

/**
 * Le client du protocole d'agent : quatre routes, et rien d'autre.
 *
 * **Aucun accès à la base, et c'est une propriété de sécurité, pas un détail.** Un agent
 * qui aurait une connexion aurait aussi besoin d'`ENCRYPTION_KEY`, c'est-à-dire de quoi
 * déchiffrer *toutes* les clés de déploiement que Zanshin détient. Il ne connaît donc du
 * plan de contrôle que ces quatre appels, authentifiés par une clé d'API portant le
 * périmètre `agent` — et il n'ouvre aucun port entrant.
 *
 * Ce fichier ne fait que parler HTTP : ce qui exécute réellement les scanners est
 * `ScanRunner`, partagé avec le travailleur intégré. C'est ce partage qui fait qu'un
 * résultat produit sur une autre machine est indiscernable d'un résultat local — mêmes
 * constats, même enrichissement, même réconciliation.
 */

/** Ce que le plan de contrôle répond à l'annonce. */
export interface AgentIdentity {
    id: string;
    name: string;
    contractVersion: string;
    maxConcurrent: number;
    credentialsMode: string;
}

/** Une tâche reçue : ce qu'un `ScanRunner` attend, plus l'identifiant à rendre. */
export type AssignedTask = ScanTask & { scanId: number };

/** Ce que l'agent annonce de lui-même. Purement informatif, sauf le contrat. */
export interface AgentDescription {
    hostname: string;
    platform: string;
    version: string;
    scannerEngine: string;
}

export class ContractMismatch extends Error {}
export class Unauthorized extends Error {}

/** L'appel HTTP, injectable : sans cela, tester le protocole demanderait un serveur. */
export type HttpCall = (
    path: string,
    init: { method: string; body?: unknown; timeoutMs: number }
) => Promise<{ status: number; body: unknown }>;

export class AgentProtocol {
    constructor(private readonly call: HttpCall) {}

    /**
     * L'annonce, et **le premier diagnostic d'un opérateur**.
     *
     * Si cet appel répond, l'URL, la clé, le périmètre et la ligne d'agent sont tous
     * corrects — c'est-à-dire l'essentiel de ce qui peut être mal configuré. Un désaccord
     * de contrat est une erreur distincte parce que son correctif l'est aussi : c'est un
     * déploiement, pas une correction de configuration.
     */
    async hello(description: AgentDescription): Promise<AgentIdentity> {
        const { status, body } = await this.call('/api/v1/agents/hello', {
            method: 'POST',
            body: {
                contract_version: CONTRACT_VERSION,
                hostname: description.hostname,
                platform: description.platform,
                version: description.version,
                scanner_engine: description.scannerEngine
            },
            timeoutMs: 30_000
        });

        if (status === 409) throw new ContractMismatch(messageOf(body) ?? 'Contrat incompatible.');
        if (status === 401 || status === 403) throw new Unauthorized(messageOf(body) ?? "Clé d'API refusée.");
        if (status >= 400) throw new Error(messageOf(body) ?? `Annonce refusée (HTTP ${status}).`);

        return body as AgentIdentity;
    }

    /**
     * Réclame une tâche, ou rend `null`.
     *
     * **204 et non un objet vide** : la question « y a-t-il du travail ? » se lit au code
     * de statut. L'attente longue est portée par le serveur — l'agent n'interroge donc pas
     * en boucle serrée, et un scan mis en file part dans la seconde plutôt qu'au prochain
     * sondage.
     */
    async claim(waitSeconds: number): Promise<AssignedTask | null> {
        const { status, body } = await this.call(`/api/v1/agents/jobs?wait=${waitSeconds}`, {
            method: 'GET',
            // Plus long que l'attente demandée : c'est le serveur qui la borne, et couper
            // au ras ferait expirer chaque sondage juste avant sa réponse.
            timeoutMs: (waitSeconds + 30) * 1000
        });

        if (status === 204) return null;
        if (status === 401 || status === 403) throw new Unauthorized(messageOf(body) ?? "Clé d'API refusée.");
        if (status === 412) {
            // La liaison n'est pas chiffrée et cet agent reçoit des clés de déploiement.
            // Refuser bruyamment est le point : scanner sans la clé produirait un échec de
            // clone qui ressemble à un problème de réseau.
            throw new Error(messageOf(body) ?? 'Liaison non chiffrée refusée pour un agent à clés déléguées.');
        }
        if (status >= 400) throw new Error(messageOf(body) ?? `Réclamation refusée (HTTP ${status}).`);

        return body as AssignedTask;
    }

    /**
     * Le signe de vie d'un agent qui travaille encore.
     *
     * Rend `false` quand le bail a été repris : l'agent doit alors **abandonner**, sans
     * quoi son résultat écraserait celui de son successeur.
     */
    async heartbeat(scanId: number): Promise<boolean> {
        const { status } = await this.call(`/api/v1/agents/jobs/${scanId}/heartbeat`, { method: 'POST', timeoutMs: 15_000 });
        if (status === 409) return false;
        if (status >= 400) throw new Error(`Signe de vie refusé (HTTP ${status}).`);
        return true;
    }

    /**
     * Rend le résultat. `false` si le bail a été repris entre-temps.
     *
     * Les noms de champs suivent le contrat, en serpent : c'est ce que le plan de contrôle
     * lit, et l'écart entre `durationMs` ici et `duration_ms` là-bas est exactement le
     * genre de détail qui se perd sans être signalé.
     */
    async submit(scanId: number, artifacts: ScanArtifacts): Promise<boolean> {
        const { status } = await this.call(`/api/v1/agents/jobs/${scanId}/result`, {
            method: 'POST',
            body: {
                sbom: artifacts.sbom,
                dependencies: artifacts.dependencies,
                secrets: artifacts.secrets,
                iac: artifacts.iac,
                sast: artifacts.sast,
                failures: artifacts.failures,
                duration_ms: artifacts.durationMs
            },
            // Un SBOM pèse plusieurs mégaoctets : le délai doit couvrir l'envoi, pas
            // seulement la réponse.
            timeoutMs: 120_000
        });

        if (status === 409) return false;
        if (status >= 400) throw new Error(`Résultat refusé (HTTP ${status}).`);
        return true;
    }
}

/** Le message d'erreur du serveur, quand il en donne un. */
function messageOf(body: unknown): string | null {
    const message = (body as { message?: unknown })?.message;
    if (typeof message === 'string') return message;
    if (Array.isArray(message)) return message.join(' ; ');
    return null;
}
