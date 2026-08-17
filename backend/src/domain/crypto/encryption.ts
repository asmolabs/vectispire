import { createCipheriv, createDecipheriv, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';

/**
 * Encryption at rest for the secrets Zanshin stores (private SSH keys, tokens).
 *
 * **Key derivation is a real KDF.** The previous implementation truncated the configured
 * secret to 32 bytes or padded it with NULs — that is not a derivation, and a short
 * passphrase was worth exactly the entropy of its characters there. It had been
 * reproduced identically from Python so that already-encrypted values stayed readable;
 * that constraint has been lifted, and the defect with it.
 *
 * Two forms of secret are accepted, in this order:
 *
 * 1. **32 random bytes in base64** — the recommended form, used as is. Nothing to
 *    stretch: the entropy is already there.
 * 2. **a passphrase** — stretched by scrypt. The salt is fixed and specific to the
 *    application: that is an accepted trade-off, a per-deployment salt would have to be
 *    stored somewhere, and scrypt's cost is enough to make a dictionary attack
 *    expensive. Without that trade-off, the only honest alternative would be to refuse
 *    passphrases — hostile for a self-hosted tool.
 *
 * The format carries a version number: `v2:base64(iv‖ciphertext‖tag)`. There is no `v1`
 * left to read, but the next format change will not have to guess.
 *
 * **The associated data binds a ciphertext to its row.** Without it, someone able to
 * write to the database would copy key A's ciphertext into row B: it would decrypt
 * cleanly, and repository A would be cloned with B's key, silently.
 */

const KEY_LENGTH_BYTES = 32;
const IV_LENGTH_BYTES = 12;
const TAG_LENGTH_BYTES = 16;
const FORMAT_PREFIX = 'v2:';

/**
 * scrypt parameters. `N = 2^15` stays under Node's default 64 MiB and costs ~100 ms —
 * imperceptible since the derivation happens **only once**, at startup.
 */
const SCRYPT = { N: 32_768, r: 8, p: 1, maxmem: 96 * 1024 * 1024 } as const;

/** Fixed salt, specific to the application. It is not a secret; see the header. */
const SCRYPT_SALT = Buffer.from('zanshin.encryption.v2', 'utf8');

/** A ciphertext's state with respect to the configured keys. */
export type SecretState = 'current' | 'previous_key' | 'unreadable';

/**
 * Derives a 32-byte key from the configured secret.
 *
 * Expensive by construction: call it once and keep the result, never once per encrypted
 * value. `EncryptionService` takes care of that.
 */
export function deriveKey(secret: string): Buffer {
    const provided = decodeExactKey(secret);
    if (provided) return provided;
    return scryptSync(secret.normalize('NFKC'), SCRYPT_SALT, KEY_LENGTH_BYTES, SCRYPT);
}

/**
 * `null` if the secret is not exactly 32 bytes encoded in base64.
 *
 * The length is checked **after** decoding: a 44-character string that is not valid
 * base64 must not be taken for a key, otherwise `Buffer.from` truncates it silently and
 * the resulting key is weaker than it looks.
 */
function decodeExactKey(secret: string): Buffer | null {
    const trimmed = secret.trim();
    if (!/^[A-Za-z0-9+/_-]{43,44}={0,2}$/.test(trimmed)) return null;
    const decoded = Buffer.from(trimmed, 'base64');
    return decoded.length === KEY_LENGTH_BYTES ? decoded : null;
}

/** A key ready to be placed in `ENCRYPTION_KEY`. */
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

/** `null` if this key does not read this value — never an exception: the caller tries
 *  several, and one exception per failure would make the normal case look like a fault. */
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
        // The GCM tag did not verify: wrong key, wrong associated data, or an altered
        // value. All three look alike, and that is intended.
        return null;
    }
}

/**
 * Tries the keys in order — the current one first, so that an already-rotated value never
 * declares itself old.
 *
 * Unlike the previous version, **there is no fallback without associated data**: that
 * fallback existed only for rows written before contexts did, and none remain. Removing
 * it removes one way of accepting a relocated ciphertext.
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

/** The identifier of where a private key lives. A single definition, because encrypting
 *  with one context and decrypting with another makes the value unreadable. */
export function privateKeyContext(keyId: string): string {
    return `ssh_key:${keyId}:private_key`;
}

/** Constant-time comparison, for the cases where the compared value is a secret. */
export function equalsSecret(left: string, right: string): boolean {
    const a = Buffer.from(left, 'utf8');
    const b = Buffer.from(right, 'utf8');
    return a.length === b.length && timingSafeEqual(a, b);
}
