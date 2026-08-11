import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { decryptWith, decryptWithAny, deriveKey, encryptWith, privateKeyContext } from './encryption';

/**
 * Vecteurs produits par le vrai service Python (`scripts` de génération dans l'historique) :
 * la seule preuve qui compte est qu'un chiffré écrit par Python se lise ici, puisque les
 * lignes déjà en base viennent de lui.
 */
const vectors = JSON.parse(readFileSync(join(__dirname, '../../../test/vectors/encryption.json'), 'utf8')) as {
    currentKey: string;
    previousKeys: string[];
    derivations: { secret: string; hex: string }[];
    cases: { name: string; plainText: string; context: string | null; encrypted: string; state?: string }[];
};

describe('chiffrement au repos', () => {
    const current = deriveKey(vectors.currentKey);
    const keys = [current, ...vectors.previousKeys.map(deriveKey)];

    describe('dérivation de clé, identique à Python', () => {
        it.each(vectors.derivations)('« $secret »', ({ secret, hex }) => {
            expect(deriveKey(secret).toString('hex')).toBe(hex);
        });

        it('complète avec des NUL plutôt que de dériver — et une clé courte vaut donc peu', () => {
            const derived = deriveKey('abc');
            expect(derived).toHaveLength(32);
            expect(derived.subarray(3).every((byte) => byte === 0)).toBe(true);
        });
    });

    describe('lecture de ce que Python a écrit', () => {
        it.each(vectors.cases)('$name', ({ plainText, context, encrypted, state }) => {
            const result = decryptWithAny(keys, encrypted, context);
            expect(result.plainText).toBe(plainText);
            expect(result.state).toBe(state ?? 'current');
        });
    });

    it('produit un format que Python relira : base64(iv‖chiffré‖tag)', () => {
        const context = privateKeyContext('11111111-1111-1111-1111-111111111111');
        const encrypted = encryptWith(current, 'secret', context);
        const raw = Buffer.from(encrypted, 'base64');
        expect(raw.length).toBe(12 + 'secret'.length + 16);
        expect(decryptWith(current, encrypted, context)).toBe('secret');
    });

    it("refuse un chiffré déplacé d'une ligne à l'autre", () => {
        // Sans cette liaison, le dépôt A serait cloné avec la clé de B, en silence.
        const encrypted = encryptWith(current, 'clé privée de A', privateKeyContext('aaaaaaaa-0000-0000-0000-000000000000'));
        expect(decryptWith(current, encrypted, privateKeyContext('bbbbbbbb-0000-0000-0000-000000000000'))).toBeNull();
        expect(decryptWithAny(keys, encrypted, privateKeyContext('bbbbbbbb-0000-0000-0000-000000000000')).state).toBe('unreadable');
    });

    it("lit une valeur écrite avant l'existence des contextes", () => {
        const encrypted = encryptWith(current, 'ancienne valeur', null);
        expect(decryptWithAny(keys, encrypted, privateKeyContext('cccccccc-0000-0000-0000-000000000000')).plainText).toBe('ancienne valeur');
    });

    it('rend « unreadable » plutôt que de lever, quand aucune clé ne lit', () => {
        const foreign = encryptWith(deriveKey('une-clé-que-personne-n-a'), 'secret', null);
        expect(decryptWithAny(keys, foreign, null)).toEqual({ plainText: '', state: 'unreadable' });
    });

    it('rend « unreadable » sur une valeur tronquée ou absurde', () => {
        for (const value of ['', 'pas du base64 !!', 'AAAA']) {
            expect(decryptWithAny(keys, value, null).state).toBe('unreadable');
        }
    });

    it('ne déclare jamais ancienne une valeur écrite avec la clé courante', () => {
        expect(decryptWithAny(keys, encryptWith(current, 'x', null), null).state).toBe('current');
    });
});
