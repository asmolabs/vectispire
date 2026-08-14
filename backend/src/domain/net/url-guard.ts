import { lookup } from 'node:dns/promises';
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

    try {
        const results = await lookup(hostname, { all: true });
        return results.map((entry) => entry.address);
    } catch {
        // Refuser sur un échec de résolution rendrait l'écran des réglages inutilisable au
        // moindre hoquet DNS, et la requête elle-même échouerait de toute façon.
        return [];
    }
}

/**
 * Les octets d'une adresse, ou `null` si ce n'en est pas une.
 *
 * **La décision se prend sur les octets, jamais sur le texte.** La version précédente
 * comparait des préfixes de chaîne, et `new URL()` normalise une adresse IPv6 avant qu'on
 * la lise : `::ffff:127.0.0.1` en ressort sous la forme hexadécimale `::ffff:7f00:1`, que
 * la reconnaissance par expression régulière ne voyait pas. La boucle locale, les réseaux
 * privés et le point de métadonnées passaient tous le garde du webhook sous cette écriture.
 */
function addressBytes(address: string): Buffer | null {
    const family = isIP(address);
    if (family === 4) return ipv4Bytes(address);
    if (family === 6) return ipv6Bytes(address);
    return null;
}

function ipv4Bytes(address: string): Buffer | null {
    const octets = address.split('.').map(Number);
    if (octets.length !== 4 || octets.some((value) => !Number.isInteger(value) || value < 0 || value > 255)) return null;
    return Buffer.from(octets);
}

function ipv6Bytes(address: string): Buffer | null {
    let text = address.toLowerCase();

    // Un dernier groupe en quatre nombres pointés — `::ffff:127.0.0.1` — devient deux
    // groupes hexadécimaux, pour n'avoir qu'une seule forme à analyser ensuite.
    const dotted = /(\d{1,3}(?:\.\d{1,3}){3})$/.exec(text);
    if (dotted) {
        const quad = ipv4Bytes(dotted[1]);
        if (!quad) return null;
        text = text.slice(0, dotted.index) + quad.readUInt16BE(0).toString(16) + ':' + quad.readUInt16BE(2).toString(16);
    }

    const halves = text.split('::');
    if (halves.length > 2) return null;
    const head = halves[0] ? halves[0].split(':') : [];
    const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
    const missing = 8 - head.length - tail.length;
    // Sans `::`, les huit groupes doivent être écrits ; avec, il en manque au moins un.
    if (halves.length === 1 ? missing !== 0 : missing < 0) return null;

    const groups = [...head, ...(halves.length === 2 ? Array<string>(missing).fill('0') : []), ...tail];
    const bytes = Buffer.alloc(16);
    for (const [index, group] of groups.entries()) {
        const value = Number.parseInt(group, 16);
        if (!Number.isInteger(value) || value < 0 || value > 0xffff) return null;
        bytes.writeUInt16BE(value, index * 2);
    }
    return bytes;
}

/** Les douze premiers octets d'une IPv6 qui en enrobe une IPv4. */
const V4_MAPPED = Buffer.from('00000000000000000000ffff', 'hex');
/** `64:ff9b::/96`, le préfixe de traduction NAT64 : les quatre derniers octets sont l'IPv4. */
const NAT64 = Buffer.from('0064ff9b0000000000000000', 'hex');

/**
 * L'IPv4 qu'une IPv6 transporte, s'il y en a une.
 *
 * Trois enrobages, et il faut les trois : `::ffff:a.b.c.d` (le courant), `64:ff9b::a.b.c.d`
 * (NAT64, qui atteint réellement l'IPv4 là où la traduction existe) et `::a.b.c.d`
 * (obsolète, toujours acceptée par les piles). Chacun est une écriture de plus pour la même
 * destination, et n'en oublier qu'une suffit à rouvrir le contournement.
 */
function embeddedV4(bytes: Buffer): Buffer | null {
    const prefix = bytes.subarray(0, 12);
    if (prefix.equals(V4_MAPPED) || prefix.equals(NAT64)) return bytes.subarray(12);
    // `::` et `::1` ne sont pas des IPv4 enrobées : ce sont l'adresse non spécifiée et la
    // boucle locale, traitées comme telles plus bas.
    if (prefix.every((octet) => octet === 0) && bytes.readUInt32BE(12) > 1) return bytes.subarray(12);
    return null;
}

/** La plage des métadonnées d'instance, en IPv4 comme en IPv6. */
function isLinkLocal(address: string): boolean {
    const bytes = addressBytes(address);
    if (!bytes) return false;

    if (bytes.length === 16) {
        const embedded = embeddedV4(bytes);
        if (embedded) return isLinkLocalV4(embedded);
        // `fe80::/10` couvre fe80 à febf.
        return bytes[0] === 0xfe && (bytes[1] & 0xc0) === 0x80;
    }
    return isLinkLocalV4(bytes);
}

function isLinkLocalV4(bytes: Buffer): boolean {
    return bytes[0] === 169 && bytes[1] === 254;
}

/**
 * L'adresse est-elle routable sur l'Internet public ?
 *
 * Écrit à la main faute d'équivalent de `ipaddress.is_global` en Node : chaque plage omise
 * ici est une destination interne qu'un webhook public pourrait atteindre.
 *
 * Une adresse illisible est déclarée non publique, ce qui la fait **refuser** côté webhook
 * et **accepter** côté Ollama. L'asymétrie est assumée : les valeurs examinées viennent soit
 * d'un littéral déjà validé par `isIP`, soit d'une résolution DNS, donc ce cas n'a pas de
 * chemin réel — et sur les deux, c'est le webhook qui est exposé à l'extérieur.
 */
function isGlobal(address: string): boolean {
    const bytes = addressBytes(address);
    if (!bytes) return false;
    return bytes.length === 16 ? isGlobalV6(bytes) : isGlobalV4(bytes);
}

function isGlobalV4(bytes: Buffer): boolean {
    const [a, b] = bytes;

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

function isGlobalV6(bytes: Buffer): boolean {
    // La décision appartient à la partie IPv4 dès qu'il y en a une.
    const embedded = embeddedV4(bytes);
    if (embedded) return isGlobalV4(embedded);

    if (bytes.every((octet) => octet === 0)) return false; // `::`, non spécifiée
    if (bytes.subarray(0, 15).every((octet) => octet === 0) && bytes[15] === 1) return false; // `::1`
    if ((bytes[0] & 0xfe) === 0xfc) return false; // fc00::/7, unique local
    if (bytes[0] === 0xfe && (bytes[1] & 0xc0) === 0x80) return false; // fe80::/10, link-local
    if (bytes[0] === 0xff) return false; // multidiffusion

    return true;
}
