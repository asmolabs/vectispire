import { createCipheriv, createDecipheriv, createHash, createPrivateKey, createPublicKey, diffieHellman, generateKeyPairSync, hkdfSync, randomBytes } from 'node:crypto';
import type { KeyObject } from 'node:crypto';

/**
 * A sealed envelope: a secret encrypted **for one specific recipient**.
 *
 * **What TLS does not give.** A repository's deployment key travels from the control
 * plane to a remote agent. TLS protects it end to end *provided nobody terminates TLS on
 * the way* — and most deployments have a reverse proxy. At that point the SSH key is in
 * the clear: in a memory dump, in a debug log, and to whoever administers the proxy.
 *
 * A sealed envelope takes that proxy out of the trust boundary. The agent publishes an
 * ephemeral public key on every claim, the control plane seals for it, and the private
 * half never leaves the agent's process — **nothing is written at rest**.
 *
 * **X25519 then AES-256-GCM.** A Diffie-Hellman exchange with an ephemeral pair on the
 * sender's side gives a shared secret; HKDF derives a session key from it; AES-GCM
 * encrypts and authenticates. This is the "sealed box" construction, written with Node's
 * primitives — no dependency added for code that handles secrets.
 *
 * **The sender's public key is covered by the authentication.** It is included in the
 * associated data: an envelope whose ephemeral key was replaced would not decrypt, rather
 * than decrypting into something else.
 */

const KEY_LENGTH_BYTES = 32;
const IV_LENGTH_BYTES = 12;
const TAG_LENGTH_BYTES = 16;

/** Distinguishes this derivation from any other using the same exchange. */
const HKDF_INFO = 'zanshin:sealed-envelope:v1';

/** An envelope's prefix. Its presence tells the agent it has to unseal. */
export const ENVELOPE_PREFIX = 'sealed:v1:';

export interface EphemeralKeyPair {
    /** To be published: it is worth nothing on its own. */
    publicKey: string;
    /** Never to be serialized. Lives in the process, dies with it. */
    privateKey: KeyObject;
}

/**
 * An ephemeral pair, for one agent process.
 *
 * Regenerated on every start and never written: a restarted agent is a new recipient, and
 * there is no key file to protect, rotate or forget.
 */
export function generateEphemeralKeyPair(): EphemeralKeyPair {
    const { publicKey, privateKey } = generateKeyPairSync('x25519');
    return {
        publicKey: publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
        privateKey
    };
}

/**
 * Seals a secret for the holder of this public key.
 *
 * Returns a prefixed string, safe to carry in JSON. Throws if the public key is
 * unreadable — **refusing is the correct behaviour**: returning the secret in the clear
 * "because sealing failed" would silently cancel the whole protection.
 */
export function seal(recipientPublicKey: string, plainText: string): string {
    const recipient = createPublicKey({
        key: Buffer.from(recipientPublicKey, 'base64'),
        format: 'der',
        type: 'spki'
    });

    // One ephemeral pair per envelope: two seals for the same recipient share no key
    // material, so compromising one does not open the other.
    const ephemeral = generateKeyPairSync('x25519');
    const ephemeralPublic = ephemeral.publicKey.export({ type: 'spki', format: 'der' });

    const shared = diffieHellman({ privateKey: ephemeral.privateKey, publicKey: recipient });
    const sessionKey = deriveSessionKey(shared, ephemeralPublic, Buffer.from(recipientPublicKey, 'base64'));

    const iv = randomBytes(IV_LENGTH_BYTES);
    const cipher = createCipheriv('aes-256-gcm', sessionKey, iv);
    // The ephemeral key as associated data: replacing it breaks authentication instead of
    // producing a different decryption.
    cipher.setAAD(ephemeralPublic);

    const cipherText = Buffer.concat([cipher.update(plainText, 'utf8'), cipher.final()]);
    const payload = Buffer.concat([ephemeralPublic, iv, cipherText, cipher.getAuthTag()]);
    return ENVELOPE_PREFIX + payload.toString('base64');
}

/**
 * Opens an envelope with the private half that matches it.
 *
 * Returns `null` for any envelope that is not exactly the expected one — wrong recipient,
 * modified content, unknown format. No exception: the caller treats failure as "I did not
 * receive the key", which is the only useful conclusion.
 */
export function open(keyPair: EphemeralKeyPair, envelope: string): string | null {
    if (!isSealed(envelope)) return null;

    try {
        const payload = Buffer.from(envelope.slice(ENVELOPE_PREFIX.length), 'base64');
        const publicKeyLength = Buffer.from(keyPair.publicKey, 'base64').length;
        if (payload.length < publicKeyLength + IV_LENGTH_BYTES + TAG_LENGTH_BYTES) return null;

        const ephemeralPublic = payload.subarray(0, publicKeyLength);
        const iv = payload.subarray(publicKeyLength, publicKeyLength + IV_LENGTH_BYTES);
        const tag = payload.subarray(payload.length - TAG_LENGTH_BYTES);
        const cipherText = payload.subarray(publicKeyLength + IV_LENGTH_BYTES, payload.length - TAG_LENGTH_BYTES);

        const shared = diffieHellman({
            privateKey: keyPair.privateKey,
            publicKey: createPublicKey({ key: ephemeralPublic, format: 'der', type: 'spki' })
        });
        const sessionKey = deriveSessionKey(shared, ephemeralPublic, Buffer.from(keyPair.publicKey, 'base64'));

        const decipher = createDecipheriv('aes-256-gcm', sessionKey, iv);
        decipher.setAAD(ephemeralPublic);
        decipher.setAuthTag(tag);
        return Buffer.concat([decipher.update(cipherText), decipher.final()]).toString('utf8');
    } catch {
        return null;
    }
}

/** Is this value a sealed envelope rather than a secret in the clear? */
export function isSealed(value: string | null | undefined): boolean {
    return typeof value === 'string' && value.startsWith(ENVELOPE_PREFIX);
}

/**
 * A readable public key?
 *
 * Checked before sealing, so the caller can refuse cleanly rather than discovering the
 * problem in an exception in the middle of a claim.
 */
export function isUsablePublicKey(value: string | null | undefined): boolean {
    if (typeof value !== 'string' || value === '') return false;
    try {
        const key = createPublicKey({ key: Buffer.from(value, 'base64'), format: 'der', type: 'spki' });
        // **Readable is not enough: it has to be an X25519 key.** An RSA key decodes
        // perfectly and will not pass the Diffie-Hellman exchange at any price — without
        // this line the refusal arrived as an exception in the middle of a claim, where
        // the whole point of this function is to decide beforehand.
        return key.asymmetricKeyType === 'x25519';
    } catch {
        return false;
    }
}

/**
 * The session key, bound to **both** public keys of the exchange.
 *
 * Including them in the salt is what stops an envelope being replayed to another
 * recipient: the shared secret would be the same, the derived key would not.
 */
function deriveSessionKey(shared: Buffer, ephemeralPublic: Buffer, recipientPublic: Buffer): Buffer {
    const salt = createHash('sha256').update(ephemeralPublic).update(recipientPublic).digest();
    return Buffer.from(hkdfSync('sha256', shared, salt, HKDF_INFO, KEY_LENGTH_BYTES));
}

/** Exposed for the tests, which need to build a recipient. */
export function publicKeyOf(keyPair: EphemeralKeyPair): string {
    return keyPair.publicKey;
}

/** Rebuilds a pair from an exported private key. Tests only. */
export function keyPairFromPrivate(privateKeyDer: Buffer): EphemeralKeyPair {
    const privateKey = createPrivateKey({ key: privateKeyDer, format: 'der', type: 'pkcs8' });
    return {
        publicKey: createPublicKey(privateKey).export({ type: 'spki', format: 'der' }).toString('base64'),
        privateKey
    };
}
