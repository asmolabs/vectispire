import { createCipheriv, createDecipheriv, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';

/**
 * Chiffrement au repos des secrets que Zanshin stocke (clés SSH privées, jetons).
 *
 * **La dérivation de clé est un vrai KDF.** L'implémentation précédente tronquait le
 * secret configuré à 32 octets ou le complétait avec des NUL — ce n'est pas une
 * dérivation, et une phrase de passe courte y valait exactement l'entropie de ses
 * caractères. Elle avait été reproduite à l'identique de Python pour que les valeurs
 * déjà chiffrées restent lisibles ; cette contrainte a été levée, et le défaut avec elle.
 *
 * Deux formes de secret sont acceptées, dans cet ordre :
 *
 * 1. **32 octets aléatoires en base64** — la forme recommandée, utilisée telle quelle.
 *    Rien à étirer : l'entropie est déjà là.
 * 2. **une phrase de passe** — étirée par scrypt. Le sel est fixe et propre à
 *    l'application : c'est un compromis assumé, un sel par déploiement demanderait de le
 *    stocker quelque part, et le coût de scrypt suffit à rendre une attaque par
 *    dictionnaire coûteuse. Sans ce compromis, la seule alternative honnête serait de
 *    refuser les phrases de passe — hostile pour un outil auto-hébergé.
 *
 * Le format porte un numéro de version : `v2:base64(iv‖chiffré‖tag)`. Il n'y a plus de
 * `v1` à lire, mais la prochaine évolution du format n'aura pas à deviner.
 *
 * **La donnée associée lie un chiffré à sa ligne.** Sans elle, quelqu'un pouvant écrire
 * en base recopierait le chiffré de la clé A dans la ligne B : il se déchiffrerait
 * proprement, et le dépôt A serait cloné avec la clé de B, en silence.
 */

const KEY_LENGTH_BYTES = 32;
const IV_LENGTH_BYTES = 12;
const TAG_LENGTH_BYTES = 16;
const FORMAT_PREFIX = 'v2:';

/**
 * Paramètres de scrypt. `N = 2^15` tient sous les 64 Mio par défaut de Node et coûte
 * ~100 ms — imperceptible puisque la dérivation n'a lieu **qu'une fois**, au démarrage.
 */
const SCRYPT = { N: 32_768, r: 8, p: 1, maxmem: 96 * 1024 * 1024 } as const;

/** Sel fixe, propre à l'application. Ce n'est pas un secret ; voir l'en-tête. */
const SCRYPT_SALT = Buffer.from('zanshin.encryption.v2', 'utf8');

/** L'état d'un chiffré vis-à-vis des clés configurées. */
export type SecretState = 'current' | 'previous_key' | 'unreadable';

/**
 * Dérive une clé de 32 octets à partir du secret configuré.
 *
 * Coûteuse par construction : à appeler une fois et à conserver, jamais par valeur
 * chiffrée. `EncryptionService` s'en charge.
 */
export function deriveKey(secret: string): Buffer {
    const provided = decodeExactKey(secret);
    if (provided) return provided;
    return scryptSync(secret.normalize('NFKC'), SCRYPT_SALT, KEY_LENGTH_BYTES, SCRYPT);
}

/**
 * `null` si le secret n'est pas exactement 32 octets encodés en base64.
 *
 * La longueur est vérifiée **après** décodage : une chaîne de 44 caractères qui n'est pas
 * du base64 valide ne doit pas être prise pour une clé, sinon `Buffer.from` la tronque en
 * silence et la clé obtenue est plus faible qu'elle n'en a l'air.
 */
function decodeExactKey(secret: string): Buffer | null {
    const trimmed = secret.trim();
    if (!/^[A-Za-z0-9+/_-]{43,44}={0,2}$/.test(trimmed)) return null;
    const decoded = Buffer.from(trimmed, 'base64');
    return decoded.length === KEY_LENGTH_BYTES ? decoded : null;
}

/** Une clé prête à être posée dans `ENCRYPTION_KEY`. */
export function generateEncryptionKey(): string {
    return randomBytes(KEY_LENGTH_BYTES).toString('base64');
}

export function encryptWith(key: Buffer, plainText: string, context?: string | null): string {
    if (!plainText) return plainText;
    const iv = randomBytes(IV_LENGTH_BYTES);
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    if (context) cipher.setAAD(Buffer.from(context, 'utf8'));
    const ciphertext = Buffer.concat([cipher.update(plainText, 'utf8'), cipher.final()]);
    return FORMAT_PREFIX + Buffer.concat([iv, ciphertext, cipher.getAuthTag()]).toString('base64');
}

/** `null` si cette clé ne lit pas cette valeur — jamais une exception : l'appelant en
 *  essaie plusieurs, et une exception par échec ferait du cas normal une anomalie. */
export function decryptWith(key: Buffer, encrypted: string, context?: string | null): string | null {
    if (!encrypted.startsWith(FORMAT_PREFIX)) return null;
    const combined = Buffer.from(encrypted.slice(FORMAT_PREFIX.length), 'base64');
    if (combined.length < IV_LENGTH_BYTES + TAG_LENGTH_BYTES) return null;

    const iv = combined.subarray(0, IV_LENGTH_BYTES);
    const tag = combined.subarray(combined.length - TAG_LENGTH_BYTES);
    const ciphertext = combined.subarray(IV_LENGTH_BYTES, combined.length - TAG_LENGTH_BYTES);
    try {
        const decipher = createDecipheriv('aes-256-gcm', key, iv);
        if (context) decipher.setAAD(Buffer.from(context, 'utf8'));
        decipher.setAuthTag(tag);
        return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
    } catch {
        // Le tag GCM n'a pas vérifié : mauvaise clé, mauvaise donnée associée, ou valeur
        // altérée. Les trois se ressemblent, et c'est voulu.
        return null;
    }
}

/**
 * Essaie les clés dans l'ordre — la courante d'abord, pour qu'une valeur déjà tournée ne
 * se déclare jamais ancienne.
 *
 * Contrairement à la version précédente, **il n'y a pas de repli sans donnée associée** :
 * ce repli n'existait que pour les lignes écrites avant l'existence des contextes, et il
 * n'en reste aucune. Le retirer supprime une façon d'accepter un chiffré déplacé.
 */
export function decryptWithAny(
    keys: readonly Buffer[],
    encrypted: string,
    context?: string | null
): { plainText: string; state: SecretState } {
    for (const [index, key] of keys.entries()) {
        const plainText = decryptWith(key, encrypted, context);
        if (plainText !== null) {
            return { plainText, state: index === 0 ? 'current' : 'previous_key' };
        }
    }
    return { plainText: '', state: 'unreadable' };
}

/** L'identifiant de l'endroit où vit une clé privée. Une seule définition, parce que
 *  chiffrer avec un contexte et déchiffrer avec un autre rend la valeur illisible. */
export function privateKeyContext(keyId: string): string {
    return `ssh_key:${keyId}:private_key`;
}

/** Comparaison à temps constant, pour les cas où la valeur comparée est un secret. */
export function equalsSecret(left: string, right: string): boolean {
    const a = Buffer.from(left, 'utf8');
    const b = Buffer.from(right, 'utf8');
    return a.length === b.length && timingSafeEqual(a, b);
}
