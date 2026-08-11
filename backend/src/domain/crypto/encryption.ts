import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

/**
 * Chiffrement au repos des secrets que Zanshin stocke (clés SSH privées, jetons).
 *
 * Le format est celui qu'écrit l'implémentation Python et **doit le rester** : les
 * lignes déjà en base ont été écrites par elle. `base64(iv‖chiffré‖tag)`, AES-256-GCM,
 * IV de 12 octets, tag de 16 — c'est exactement ce que produit `AESGCM.encrypt` de
 * `cryptography`, qui accole le tag au chiffré.
 *
 * **La dérivation de clé n'est pas un KDF** : elle tronque à 32 octets ou complète avec
 * des NUL. C'est reproduit à l'octet près, non par approbation mais parce que passer à
 * un vrai KDF rendrait illisible tout ce qui est déjà stocké. Conséquence à connaître :
 * une phrase de passe courte ne vaut que l'entropie qu'elle contient — il faut fournir
 * 32 octets aléatoires.
 *
 * **La donnée associée lie un chiffré à sa ligne.** Sans elle, quelqu'un pouvant écrire
 * en base recopierait le chiffré de la clé A dans la ligne B : il se déchiffrerait
 * proprement, et le dépôt A serait cloné avec la clé de B, en silence. Le coût est une
 * chaîne ; le bénéfice est que l'échange échoue bruyamment.
 */

const KEY_LENGTH_BYTES = 32;
const IV_LENGTH_BYTES = 12;
const TAG_LENGTH_BYTES = 16;

/** L'état d'un chiffré vis-à-vis des clés configurées. */
export type SecretState = 'current' | 'previous_key' | 'unreadable';

/** Tronque ou complète avec des NUL, à l'identique de Python. */
export function deriveKey(secret: string): Buffer {
    const raw = Buffer.from(secret, 'utf8');
    if (raw.length >= KEY_LENGTH_BYTES) return raw.subarray(0, KEY_LENGTH_BYTES);
    const padded = Buffer.alloc(KEY_LENGTH_BYTES);
    raw.copy(padded);
    return padded;
}

export function encryptWith(key: Buffer, plainText: string, context?: string | null): string {
    if (!plainText) return plainText;
    const iv = randomBytes(IV_LENGTH_BYTES);
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    if (context) cipher.setAAD(Buffer.from(context, 'utf8'));
    const ciphertext = Buffer.concat([cipher.update(plainText, 'utf8'), cipher.final()]);
    return Buffer.concat([iv, ciphertext, cipher.getAuthTag()]).toString('base64');
}

/** `null` si cette clé ne lit pas cette valeur — jamais une exception : l'appelant en
 *  essaie plusieurs, et une exception par échec ferait du cas normal une anomalie. */
export function decryptWith(key: Buffer, encrypted: string, context?: string | null): string | null {
    let combined: Buffer;
    try {
        combined = Buffer.from(encrypted, 'base64');
    } catch {
        return null;
    }
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
        return null;
    }
}

/**
 * Essaie les clés dans l'ordre — la courante d'abord, pour qu'une valeur déjà tournée
 * ne se déclare jamais ancienne.
 *
 * Pour chaque clé, la donnée associée attendue est essayée, puis l'absence de donnée
 * associée : les lignes antérieures à ce mécanisme n'en portent pas. Le repli **n'essaie
 * pas une autre donnée associée**, ce qui annulerait la liaison.
 */
export function decryptWithAny(
    keys: readonly Buffer[],
    encrypted: string,
    context?: string | null
): { plainText: string; state: SecretState } {
    for (const [index, key] of keys.entries()) {
        for (const aad of context ? [context, null] : [null]) {
            const plainText = decryptWith(key, encrypted, aad);
            if (plainText !== null) {
                return { plainText, state: index === 0 ? 'current' : 'previous_key' };
            }
        }
    }
    return { plainText: '', state: 'unreadable' };
}

/** L'identifiant de l'endroit où vit une clé privée. Une seule définition, parce que
 *  chiffrer avec un contexte et déchiffrer avec un autre rend la valeur illisible. */
export function privateKeyContext(keyId: string): string {
    return `ssh_key:${keyId}:private_key`;
}
