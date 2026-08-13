import { isIP } from 'node:net';

/**
 * La validation des URL vers lesquelles Zanshin émettra une requête.
 *
 * Trois réglages deviennent des requêtes côté serveur : le webhook de notification, le
 * serveur Ollama, et l'API de scan locale. Chacun est une chaîne posée par un
 * administrateur puis appelée par le serveur — c'est une primitive de falsification de
 * requête côté serveur, dont la cible classique est le point d'accès de métadonnées
 * (`169.254.169.254`), qui remet les identifiants de l'instance à qui les demande.
 *
 * « Seul un administrateur peut le régler » est une atténuation, pas une réponse : un
 * administrateur de Zanshin n'est pas nécessairement quelqu'un d'habilité à lire les
 * identifiants IAM de l'hôte, et c'est exactement le pivot que cherche un attaquant ayant
 * hameçonné un compte.
 *
 * **Le problème des adresses privées.** Les bloquer purement et simplement casserait deux
 * des trois réglages par construction — Ollama et l'annexe de scan sont *censés* être sur
 * la boucle locale ou le réseau interne. La règle est donc par usage :
 *
 * - `allowPrivate: false` (le webhook) : destinations publiques seulement.
 * - `allowPrivate: true` (l'annexe) : privé et boucle locale acceptés, mais le link-local
 *   — la plage des métadonnées — jamais. Rien de légitime ne vit en 169.254.0.0/16, et
 *   c'est précisément l'adresse que l'attaque veut.
 * - `requirePrivate: true` (Ollama) : l'image inverse, et celle qu'on rate facilement.
 *   Ollama reçoit le **code source** du dépôt scanné : le risque n'est pas que l'URL
 *   pointe vers l'interne, c'est qu'elle pointe vers l'**externe**. Une URL publique et
 *   bien formée est exactement ce à quoi ressemble un canal d'exfiltration, et aucune
 *   vérification anti-SSRF ne la signalerait.
 *
 * Le DNS est résolu ici pour qu'un nom pointant vers une adresse bloquée soit refusé lui
 * aussi. Cela laisse une fenêtre de reliaison entre cette vérification et la requête
 * elle-même, que ceci ne peut pas fermer : il faudrait épingler l'adresse résolue dans le
 * client HTTP. Consigné comme limite connue plutôt que masqué.
 */

const ALLOWED_SCHEMES = ['https:', 'http:'];

/** L'URL n'est pas une destination que Zanshin appellera. */
export class UnsafeUrlError extends Error {}

export interface UrlGuardOptions {
    allowPrivate: boolean;
    requirePrivate?: boolean;
    label?: string;
    /** Injectable : la résolution DNS ne doit pas être une dépendance des tests. */
    resolve?: (hostname: string) => Promise<string[]>;
}

/** Rend l'URL nettoyée, ou lève `UnsafeUrlError`. */
export async function validateOutboundUrl(url: string, options: UrlGuardOptions): Promise<string> {
    const { allowPrivate, requirePrivate = false, label = 'URL', resolve = resolveHostname } = options;
    const candidate = (url ?? '').trim();
    if (!candidate) throw new UnsafeUrlError(`${label} : valeur vide.`);

    let parsed: URL;
    try {
        parsed = new URL(candidate);
    } catch {
        throw new UnsafeUrlError(`${label} : URL illisible.`);
    }

    if (!ALLOWED_SCHEMES.includes(parsed.protocol.toLowerCase())) {
        throw new UnsafeUrlError(`${label} : schéma « ${parsed.protocol || '(aucun)'} » non autorisé (attendu : https, http).`);
    }
    // `URL` retire les crochets d'une adresse IPv6 littérale ; `hostname` est donc
    // directement comparable.
    const hostname = parsed.hostname.replace(/^\[|\]$/g, '');
    if (!hostname) throw new UnsafeUrlError(`${label} : hôte manquant.`);

    const addresses = await resolve(hostname);

    if (requirePrivate && addresses.length === 0) {
        // Échouer ouvert est défendable pour « est-ce privé ? » : la requête échouerait de
        // toute façon. Ça ne l'est pas pour « ceci **doit** être privé » — un nom
        // irrésoluble ne prouve rien, et cette vérification est ce qui sépare le code
        // source scanné d'un hôte externe.
        throw new UnsafeUrlError(
            `${label} : l'hôte n'a pas pu être résolu, donc son caractère interne ne peut pas être vérifié — ` +
                'et ce point de terminaison reçoit du code source.'
        );
    }

    for (const address of addresses) {
        if (isLinkLocal(address)) {
            throw new UnsafeUrlError(
                `${label} : l'hôte résout vers une adresse link-local (${address}), utilisée par les services de métadonnées d'instance.`
            );
        }
        const global = isGlobal(address);
        if (!allowPrivate && !global) {
            throw new UnsafeUrlError(
                `${label} : l'hôte résout vers une adresse privée ou locale (${address}). Une destination publique est attendue ici.`
            );
        }
        if (requirePrivate && global) {
            throw new UnsafeUrlError(
                `${label} : l'hôte résout vers une adresse publique (${address}). Une destination locale ou interne est attendue ` +
                    'ici — ce point de terminaison reçoit du code source.'
            );
        }
    }
    return candidate;
}

/** Variante qui ne lève pas : la raison, ou `null` quand l'URL est acceptable. */
export async function unsafeReason(url: string, options: UrlGuardOptions): Promise<string | null> {
    try {
        await validateOutboundUrl(url, options);
        return null;
    } catch (error) {
        if (error instanceof UnsafeUrlError) return error.message;
        throw error;
    }
}

/**
 * Toutes les adresses vers lesquelles un nom résout.
 *
 * **Toutes, pas la première** : un nom peut rendre une adresse publique et une adresse
 * privée, et n'en vérifier qu'une laisserait passer l'autre.
 */
async function resolveHostname(hostname: string): Promise<string[]> {
    if (isIP(hostname)) return [hostname];

    // Importé ici plutôt qu'en tête : le module de résolution n'a rien à faire dans un
    // arbre de dépendances chargé par des tests qui injectent leur propre résolution.
    const { lookup } = await import('node:dns/promises');
    try {
        const results = await lookup(hostname, { all: true });
        return results.map((entry) => entry.address);
    } catch {
        // Refuser sur un échec de résolution rendrait l'écran des réglages inutilisable au
        // moindre hoquet DNS, et la requête elle-même échouerait de toute façon.
        return [];
    }
}

/** La plage des métadonnées d'instance, en IPv4 comme en IPv6. */
function isLinkLocal(address: string): boolean {
    if (address.startsWith('169.254.')) return true;
    const lower = address.toLowerCase();
    // `fe80::/10` couvre fe80 à febf.
    return /^fe[89ab]/.test(lower);
}

/**
 * L'adresse est-elle routable sur l'Internet public ?
 *
 * Écrit à la main faute d'équivalent de `ipaddress.is_global` en Node : chaque plage
 * omise ici est une destination interne qu'un webhook public pourrait atteindre.
 */
function isGlobal(address: string): boolean {
    if (isIP(address) === 6) return isGlobalV6(address.toLowerCase());

    const octets = address.split('.').map(Number);
    if (octets.length !== 4 || octets.some((value) => !Number.isInteger(value))) return false;
    const [a, b] = octets;

    if (a === 0 || a === 10 || a === 127) return false;
    if (a === 100 && b >= 64 && b <= 127) return false; // CGNAT, 100.64.0.0/10
    if (a === 169 && b === 254) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && b === 168) return false;
    if (a === 192 && b === 0) return false; // 192.0.0.0/24 et 192.0.2.0/24
    if (a === 198 && (b === 18 || b === 19)) return false; // bancs d'essai
    if (a === 198 && b === 51) return false;
    if (a === 203 && b === 0) return false;
    if (a >= 224) return false; // multidiffusion et réservé

    return true;
}

function isGlobalV6(address: string): boolean {
    if (address === '::1' || address === '::') return false;
    if (address.startsWith('fc') || address.startsWith('fd')) return false; // unique local
    if (/^fe[89ab]/.test(address)) return false;
    if (address.startsWith('ff')) return false; // multidiffusion
    // Adresse IPv4 encapsulée : la décision appartient à la partie IPv4.
    const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(address);
    if (mapped) return isGlobal(mapped[1]);
    return true;
}
