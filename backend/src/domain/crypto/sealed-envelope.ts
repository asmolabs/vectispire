import { createCipheriv, createDecipheriv, createHash, createPrivateKey, createPublicKey, diffieHellman, generateKeyPairSync, hkdfSync, randomBytes } from 'node:crypto';
import type { KeyObject } from 'node:crypto';

/**
 * Une enveloppe scellée : un secret chiffré **pour un destinataire précis**.
 *
 * **Ce que TLS ne donne pas.** La clé de déploiement d'un dépôt voyage du plan de contrôle
 * vers un agent distant. TLS la protège de bout en bout *à condition que personne ne
 * termine TLS en chemin* — or la plupart des déploiements ont un proxy inverse. À cet
 * endroit, la clé SSH est en clair : dans un vidage mémoire, dans un journal de débogage,
 * et pour qui administre le proxy.
 *
 * Une enveloppe scellée retire ce proxy de la frontière de confiance. L'agent publie une
 * clé publique éphémère à chaque réclamation, le plan de contrôle scelle pour elle, et la
 * moitié privée ne quitte jamais le processus de l'agent — **rien n'est écrit au repos**.
 *
 * **X25519 puis AES-256-GCM.** Un échange Diffie-Hellman avec une paire éphémère côté
 * expéditeur donne un secret partagé ; HKDF en tire une clé de session ; AES-GCM chiffre
 * et authentifie. C'est la construction d'une « boîte scellée », écrite avec les primitives
 * de Node — aucune dépendance ajoutée pour du code qui manipule des secrets.
 *
 * **La clé publique de l'expéditeur est couverte par l'authentification.** Elle est incluse
 * dans les données associées : une enveloppe dont on remplacerait la clé éphémère ne se
 * déchiffrerait pas, au lieu de se déchiffrer en autre chose.
 */

const KEY_LENGTH_BYTES = 32;
const IV_LENGTH_BYTES = 12;
const TAG_LENGTH_BYTES = 16;

/** Distingue cette dérivation de toute autre usant du même échange. */
const HKDF_INFO = 'zanshin:sealed-envelope:v1';

/** Le préfixe d'une enveloppe. Sa présence dit à l'agent qu'il doit déceler. */
export const ENVELOPE_PREFIX = 'sealed:v1:';

export interface EphemeralKeyPair {
    /** À publier : elle ne vaut rien seule. */
    publicKey: string;
    /** À ne jamais sérialiser. Vit dans le processus, meurt avec lui. */
    privateKey: KeyObject;
}

/**
 * Une paire éphémère, pour un processus d'agent.
 *
 * Régénérée à chaque démarrage et jamais écrite : un agent redémarré est un nouveau
 * destinataire, et il n'y a aucun fichier de clé à protéger, tourner ou oublier.
 */
export function generateEphemeralKeyPair(): EphemeralKeyPair {
    const { publicKey, privateKey } = generateKeyPairSync('x25519');
    return {
        publicKey: publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
        privateKey
    };
}

/**
 * Scelle un secret pour le porteur de cette clé publique.
 *
 * Rend une chaîne préfixée, sûre à transporter en JSON. Lève si la clé publique est
 * illisible — **refuser est le comportement correct** : rendre le secret en clair « parce
 * que le scellement a échoué » annulerait silencieusement toute la protection.
 */
export function seal(recipientPublicKey: string, plainText: string): string {
    const recipient = createPublicKey({
        key: Buffer.from(recipientPublicKey, 'base64'),
        format: 'der',
        type: 'spki'
    });

    // Paire éphémère par enveloppe : deux scellements pour le même destinataire ne
    // partagent aucun matériel, donc compromettre l'un n'ouvre pas l'autre.
    const ephemeral = generateKeyPairSync('x25519');
    const ephemeralPublic = ephemeral.publicKey.export({ type: 'spki', format: 'der' });

    const shared = diffieHellman({ privateKey: ephemeral.privateKey, publicKey: recipient });
    const sessionKey = deriveSessionKey(shared, ephemeralPublic, Buffer.from(recipientPublicKey, 'base64'));

    const iv = randomBytes(IV_LENGTH_BYTES);
    const cipher = createCipheriv('aes-256-gcm', sessionKey, iv);
    // La clé éphémère en données associées : la remplacer casse l'authentification au lieu
    // de produire un autre déchiffrement.
    cipher.setAAD(ephemeralPublic);

    const cipherText = Buffer.concat([cipher.update(plainText, 'utf8'), cipher.final()]);
    const payload = Buffer.concat([ephemeralPublic, iv, cipherText, cipher.getAuthTag()]);
    return ENVELOPE_PREFIX + payload.toString('base64');
}

/**
 * Ouvre une enveloppe avec la moitié privée qui lui correspond.
 *
 * Rend `null` sur toute enveloppe qui n'est pas exactement celle attendue — mauvais
 * destinataire, contenu modifié, format inconnu. Pas d'exception : l'appelant traite
 * l'échec comme « je n'ai pas reçu la clé », qui est la seule conclusion utile.
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

/** Cette valeur est-elle une enveloppe scellée plutôt qu'un secret en clair ? */
export function isSealed(value: string | null | undefined): boolean {
    return typeof value === 'string' && value.startsWith(ENVELOPE_PREFIX);
}

/**
 * Une clé publique lisible ?
 *
 * Vérifié avant de sceller, pour que l'appelant puisse refuser proprement plutôt que de
 * découvrir le problème dans une exception au milieu d'une réclamation.
 */
export function isUsablePublicKey(value: string | null | undefined): boolean {
    if (typeof value !== 'string' || value === '') return false;
    try {
        createPublicKey({ key: Buffer.from(value, 'base64'), format: 'der', type: 'spki' });
        return true;
    } catch {
        return false;
    }
}

/**
 * La clé de session, liée aux **deux** clés publiques de l'échange.
 *
 * Les inclure dans le sel est ce qui empêche de rejouer une enveloppe vers un autre
 * destinataire : le secret partagé serait le même, la clé dérivée non.
 */
function deriveSessionKey(shared: Buffer, ephemeralPublic: Buffer, recipientPublic: Buffer): Buffer {
    const salt = createHash('sha256').update(ephemeralPublic).update(recipientPublic).digest();
    return Buffer.from(hkdfSync('sha256', shared, salt, HKDF_INFO, KEY_LENGTH_BYTES));
}

/** Rendu pour les tests, qui ont besoin de fabriquer un destinataire. */
export function publicKeyOf(keyPair: EphemeralKeyPair): string {
    return keyPair.publicKey;
}

/** Reconstruit une paire depuis une clé privée exportée. Réservé aux tests. */
export function keyPairFromPrivate(privateKeyDer: Buffer): EphemeralKeyPair {
    const privateKey = createPrivateKey({ key: privateKeyDer, format: 'der', type: 'pkcs8' });
    return {
        publicKey: createPublicKey(privateKey).export({ type: 'spki', format: 'der' }).toString('base64'),
        privateKey
    };
}
