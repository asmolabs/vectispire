import { generateKeyPairSync } from 'node:crypto';
import { ENVELOPE_PREFIX, generateEphemeralKeyPair, isSealed, isUsablePublicKey, open, seal } from './sealed-envelope';

/**
 * The sealed envelope, exercised on its failures as much as on its nominal case.
 *
 * A crypto module tested only on the case that works proves nothing: the most dangerous
 * sealing is the one that *appears* to work — an envelope that opens for the wrong
 * recipient, or whose content can be modified without opening failing.
 */
describe('sealed envelope', () => {
    const SECRET = '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----\n';

    it('gives the recipient exactly what was sealed', () => {
        const agent = generateEphemeralKeyPair();

        expect(open(agent, seal(agent.publicKey, SECRET))).toBe(SECRET);
    });

    it("does not open with another recipient's key", () => {
        // The point of the whole construction: without it, any registered agent would
        // open the envelopes meant for the others.
        const destinataire = generateEphemeralKeyPair();
        const autre = generateEphemeralKeyPair();

        expect(open(autre, seal(destinataire.publicKey, SECRET))).toBeNull();
    });

    it('refuses an envelope whose content was modified', () => {
        const agent = generateEphemeralKeyPair();
        const envelope = seal(agent.publicKey, SECRET);

        // One byte flipped in the middle of the ciphertext. AES-GCM authenticates:
        // opening must fail, not return damaged text an agent would write into a key file.
        const raw = Buffer.from(envelope.slice(ENVELOPE_PREFIX.length), 'base64');
        raw[Math.floor(raw.length / 2)] ^= 0x01;

        expect(open(agent, ENVELOPE_PREFIX + raw.toString('base64'))).toBeNull();
    });

    it('refuses an envelope whose ephemeral key was replaced', () => {
        // This is what the associated data covers. Without it, substituting the sender's
        // public key would give a different derivation instead of a rejection.
        const agent = generateEphemeralKeyPair();
        const envelope = seal(agent.publicKey, SECRET);
        const raw = Buffer.from(envelope.slice(ENVELOPE_PREFIX.length), 'base64');

        const intrus = generateKeyPairSync('x25519').publicKey.export({
            type: 'spki',
            format: 'der'
        });
        intrus.copy(raw, 0);

        expect(open(agent, ENVELOPE_PREFIX + raw.toString('base64'))).toBeNull();
    });

    it('produces two different envelopes for the same secret', () => {
        // One ephemeral pair per envelope: two scans of the same repository must not
        // produce the same ciphertext, otherwise an eavesdropper would learn it is the
        // same secret.
        const agent = generateEphemeralKeyPair();

        expect(seal(agent.publicKey, SECRET)).not.toBe(seal(agent.publicKey, SECRET));
    });

    it('throws rather than returning the secret in the clear on an unreadable key', () => {
        // **Refuser est le comportement correct.** Retomber sur le clair « parce que le
        // sealing failed" would silently cancel the whole protection, and the operator
        // would see no difference.
        expect(() => seal('not-a-key', SECRET)).toThrow();
    });

    it('recognizes an envelope and does not mistake a cleartext secret for one', () => {
        const agent = generateEphemeralKeyPair();

        expect(isSealed(seal(agent.publicKey, SECRET))).toBe(true);
        expect(isSealed(SECRET)).toBe(false);
        expect(isSealed(null)).toBe(false);
    });

    it('returns null for what is not an envelope, without throwing', () => {
        // The caller is an agent that treats failure as "I did not receive the key";
        // une exception le ferait planter sur une valeur qu'il n'a pas choisie.
        const agent = generateEphemeralKeyPair();

        expect(open(agent, SECRET)).toBeNull();
        expect(open(agent, ENVELOPE_PREFIX + 'pas-du-base64-valide!!')).toBeNull();
        expect(open(agent, ENVELOPE_PREFIX)).toBeNull();
    });

    it('judges a public key before anyone tries to seal for it', () => {
        expect(isUsablePublicKey(generateEphemeralKeyPair().publicKey)).toBe(true);
        expect(isUsablePublicKey('')).toBe(false);
        expect(isUsablePublicKey(null)).toBe(false);
        expect(isUsablePublicKey('bm9uLXVuZS1jbGU=')).toBe(false);
        // An RSA key is readable but unsuitable for an X25519 exchange: rejecting it here
        // avoids an exception in the middle of a claim.
        const rsa = generateKeyPairSync('rsa', {
            modulusLength: 2048
        }).publicKey.export({ type: 'spki', format: 'der' });
        expect(isUsablePublicKey(rsa.toString('base64'))).toBe(false);
    });

    it('gives a different pair to every agent that starts', () => {
        // No key file to protect, rotate or forget: a restarted agent is a
        // nouveau destinataire.
        expect(generateEphemeralKeyPair().publicKey).not.toBe(generateEphemeralKeyPair().publicKey);
    });
});
