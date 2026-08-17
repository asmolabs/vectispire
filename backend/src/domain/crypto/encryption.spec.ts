import { decryptWith, decryptWithAny, deriveKey, encryptWith, equalsSecret, generateEncryptionKey, privateKeyContext } from './encryption';

describe('encryption at rest', () => {
    const PASSPHRASE = 'une phrase de passe choisie par un humain';
    const key = deriveKey(PASSPHRASE);
    const previous = deriveKey('the previous passphrase');
    const keys = [key, previous];

    describe('derivation', () => {
        it('accepts a 32-byte base64 key as is', () => {
            const generated = generateEncryptionKey();
            expect(Buffer.from(generated, 'base64')).toHaveLength(32);
            expect(deriveKey(generated).equals(Buffer.from(generated, 'base64'))).toBe(true);
        });

        it('stretches a passphrase rather than truncating it', () => {
            // The previous implementation returned "abc" followed by 29 null bytes: the
            // key was worth the entropy of the three characters. That is the fixed defect.
            const derived = deriveKey('abc');
            expect(derived).toHaveLength(32);
            expect(derived.subarray(3).some((byte) => byte !== 0)).toBe(true);
        });

        it('is deterministic, without which nothing would read back after a restart', () => {
            expect(deriveKey(PASSPHRASE).equals(deriveKey(PASSPHRASE))).toBe(true);
        });

        it('gives distinct keys for neighbouring passphrases', () => {
            expect(deriveKey('phrase-a').equals(deriveKey('phrase-b'))).toBe(false);
        });

        it("normalizes unicode, so the same word typed differently opens the same lock", () => {
            // Composed and decomposed "é" are visually identical and differ in bytes:
            // without normalization, the operator who retypes their passphrase from
            // another system ends up facing unreadable secrets.
            //
            // **The two literals below are not the same bytes**, however identical they
            // look in an editor: the first is U+00E9, the second "e" followed by the
            // combining acute U+0301. They are written with escapes rather than as raw
            // characters because the difference is invisible on screen, and a
            // well-meaning cleanup that collapsed them would leave a test passing
            // without any normalization at all.
            const composed = 'cl\u00e9-de-chiffrement';
            const decomposed = 'cle\u0301-de-chiffrement';
            expect(composed).not.toBe(decomposed);
            expect(deriveKey(composed).equals(deriveKey(decomposed))).toBe(true);
        });

        it("does not take a right-length string that is not base64 for a key", () => {
            // Otherwise `Buffer.from` truncates it silently and the key is weaker than it
            // looks.
            const notBase64 = '!'.repeat(44);
            expect(deriveKey(notBase64).equals(Buffer.from(notBase64, 'base64'))).toBe(false);
        });
    });

    describe('round trip', () => {
        it('reads back what it wrote, context included', () => {
            const context = privateKeyContext('11111111-1111-1111-1111-111111111111');
            const encrypted = encryptWith(key, 'private key', context);
            expect(encrypted.startsWith('v2:')).toBe(true);
            expect(decryptWith(key, encrypted, context)).toBe('private key');
        });

        it('preserves accents and non-Latin characters', () => {
            // Kept non-ASCII on purpose: this test exists to prove the round trip is
            // byte-exact through UTF-8, so translating the sample away would delete what
            // it checks. An SSH key comment or a passphrase can hold any of these.
            const sample = 'private key é à ü 漢字';
            const encrypted = encryptWith(key, sample, null);
            expect(decryptWith(key, encrypted, null)).toBe(sample);
        });

        it('does not repeat a ciphertext for the same plaintext', () => {
            // The IV is drawn on every call: two identical ciphertexts would reveal that
            // two rows carry the same secret.
            expect(encryptWith(key, 'same plaintext', null)).not.toBe(encryptWith(key, 'same plaintext', null));
        });

        it('leaves an empty string as is', () => {
            expect(encryptWith(key, '', null)).toBe('');
        });
    });

    describe('binding to the row', () => {
        it("refuses a ciphertext moved from one row to another", () => {
            const encrypted = encryptWith(key, "A's private key", privateKeyContext('aaaaaaaa-0000-0000-0000-000000000000'));
            const elsewhere = privateKeyContext('bbbbbbbb-0000-0000-0000-000000000000');
            expect(decryptWith(key, encrypted, elsewhere)).toBeNull();
            expect(decryptWithAny(keys, encrypted, elsewhere).state).toBe('unreadable');
        });

        it('does not fall back to the absence of associated data', () => {
            // That fallback existed for rows predating contexts; none remain, and
            // removing it removes one way of accepting a relocated ciphertext.
            const encrypted = encryptWith(key, 'bound', privateKeyContext('cccccccc-0000-0000-0000-000000000000'));
            expect(decryptWith(key, encrypted, null)).toBeNull();
        });
    });

    describe('rotation', () => {
        it('declares current what is written with the current key', () => {
            expect(decryptWithAny(keys, encryptWith(key, 'x', null), null).state).toBe('current');
        });

        it('declares previous_key what has not yet been re-saved', () => {
            expect(decryptWithAny(keys, encryptWith(previous, 'x', null), null)).toEqual({ plainText: 'x', state: 'previous_key' });
        });

        it('returns unreadable rather than throwing, when no key reads', () => {
            const foreign = encryptWith(deriveKey('a key nobody has'), 'x', null);
            expect(decryptWithAny(keys, foreign, null)).toEqual({ plainText: '', state: 'unreadable' });
        });
    });

    describe('malformed values', () => {
        it.each([[''], ['not base64 !!'], ['v2:AAAA'], ['v2:'], ['no-prefix'], ['v1:AAAA']])('returns unreadable for %p', (value) => {
            expect(decryptWithAny(keys, value, null).state).toBe('unreadable');
        });

        it('detects tampering with the tag', () => {
            const encrypted = encryptWith(key, 'intact', null);
            const tampered = encrypted.slice(0, -4) + (encrypted.endsWith('AAAA') ? 'BBBB' : 'AAAA');
            expect(decryptWith(key, tampered, null)).toBeNull();
        });
    });

    it('compares two secrets in constant time', () => {
        expect(equalsSecret('secret', 'secret')).toBe(true);
        expect(equalsSecret('secret', 'secrez')).toBe(false);
        expect(equalsSecret('secret', 'secret-plus-long')).toBe(false);
    });
});
