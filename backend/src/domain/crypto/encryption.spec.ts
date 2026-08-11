import { decryptWith, decryptWithAny, deriveKey, encryptWith, equalsSecret, generateEncryptionKey, privateKeyContext } from './encryption';

describe('chiffrement au repos', () => {
    const PASSPHRASE = 'une phrase de passe choisie par un humain';
    const key = deriveKey(PASSPHRASE);
    const previous = deriveKey('la phrase précédente');
    const keys = [key, previous];

    describe('dérivation', () => {
        it('accepte une clé de 32 octets en base64 telle quelle', () => {
            const generated = generateEncryptionKey();
            expect(Buffer.from(generated, 'base64')).toHaveLength(32);
            expect(deriveKey(generated).equals(Buffer.from(generated, 'base64'))).toBe(true);
        });

        it('étire une phrase de passe plutôt que de la tronquer', () => {
            // L'implémentation précédente rendait « abc » suivi de 29 octets nuls : la
            // clé valait l'entropie des trois caractères. C'est le défaut corrigé.
            const derived = deriveKey('abc');
            expect(derived).toHaveLength(32);
            expect(derived.subarray(3).some((byte) => byte !== 0)).toBe(true);
        });

        it('est déterministe, sans quoi rien ne se relirait après un redémarrage', () => {
            expect(deriveKey(PASSPHRASE).equals(deriveKey(PASSPHRASE))).toBe(true);
        });

        it('donne des clés distinctes pour des phrases voisines', () => {
            expect(deriveKey('phrase-a').equals(deriveKey('phrase-b'))).toBe(false);
        });

        it("normalise l'unicode, pour qu'un même mot saisi autrement ouvre la même serrure", () => {
            // « é » composé et décomposé sont visuellement identiques et différents en
            // octets : sans normalisation, l'opérateur qui recopie sa phrase depuis un
            // autre système se retrouve devant des secrets illisibles.
            expect(deriveKey('clé-de-chiffrement').equals(deriveKey('clé-de-chiffrement'))).toBe(true);
        });

        it("ne prend pas pour une clé une chaîne de la bonne longueur qui n'est pas du base64", () => {
            // Sinon `Buffer.from` la tronque en silence et la clé est plus faible qu'elle
            // n'en a l'air.
            const notBase64 = '!'.repeat(44);
            expect(deriveKey(notBase64).equals(Buffer.from(notBase64, 'base64'))).toBe(false);
        });
    });

    describe('aller-retour', () => {
        it('relit ce qu’il a écrit, contexte compris', () => {
            const context = privateKeyContext('11111111-1111-1111-1111-111111111111');
            const encrypted = encryptWith(key, 'clé privée', context);
            expect(encrypted.startsWith('v2:')).toBe(true);
            expect(decryptWith(key, encrypted, context)).toBe('clé privée');
        });

        it('préserve les accents et les caractères non latins', () => {
            const encrypted = encryptWith(key, 'clé privée é à ü 漢字', null);
            expect(decryptWith(key, encrypted, null)).toBe('clé privée é à ü 漢字');
        });

        it('ne répète pas un chiffré pour un même clair', () => {
            // L'IV est tiré à chaque appel : deux chiffrés identiques révéleraient que
            // deux lignes portent le même secret.
            expect(encryptWith(key, 'même clair', null)).not.toBe(encryptWith(key, 'même clair', null));
        });

        it('laisse une chaîne vide telle quelle', () => {
            expect(encryptWith(key, '', null)).toBe('');
        });
    });

    describe('liaison à la ligne', () => {
        it("refuse un chiffré déplacé d'une ligne à l'autre", () => {
            const encrypted = encryptWith(key, 'clé privée de A', privateKeyContext('aaaaaaaa-0000-0000-0000-000000000000'));
            const elsewhere = privateKeyContext('bbbbbbbb-0000-0000-0000-000000000000');
            expect(decryptWith(key, encrypted, elsewhere)).toBeNull();
            expect(decryptWithAny(keys, encrypted, elsewhere).state).toBe('unreadable');
        });

        it('ne se rabat pas sur l’absence de donnée associée', () => {
            // Ce repli existait pour les lignes antérieures aux contextes ; il n'en reste
            // aucune, et le retirer supprime une façon d'accepter un chiffré déplacé.
            const encrypted = encryptWith(key, 'lié', privateKeyContext('cccccccc-0000-0000-0000-000000000000'));
            expect(decryptWith(key, encrypted, null)).toBeNull();
        });
    });

    describe('rotation', () => {
        it('déclare « current » ce qui est écrit avec la clé courante', () => {
            expect(decryptWithAny(keys, encryptWith(key, 'x', null), null).state).toBe('current');
        });

        it('déclare « previous_key » ce qui n’a pas encore été réenregistré', () => {
            expect(decryptWithAny(keys, encryptWith(previous, 'x', null), null)).toEqual({ plainText: 'x', state: 'previous_key' });
        });

        it('rend « unreadable » plutôt que de lever, quand aucune clé ne lit', () => {
            const foreign = encryptWith(deriveKey('une clé que personne n’a'), 'x', null);
            expect(decryptWithAny(keys, foreign, null)).toEqual({ plainText: '', state: 'unreadable' });
        });
    });

    describe('valeurs mal formées', () => {
        it.each([[''], ['pas du base64 !!'], ['v2:AAAA'], ['v2:'], ['sans-prefixe'], ['v1:AAAA']])('rend « unreadable » sur %p', (value) => {
            expect(decryptWithAny(keys, value, null).state).toBe('unreadable');
        });

        it('détecte une altération du tag', () => {
            const encrypted = encryptWith(key, 'intact', null);
            const tampered = encrypted.slice(0, -4) + (encrypted.endsWith('AAAA') ? 'BBBB' : 'AAAA');
            expect(decryptWith(key, tampered, null)).toBeNull();
        });
    });

    it('compare deux secrets à temps constant', () => {
        expect(equalsSecret('secret', 'secret')).toBe(true);
        expect(equalsSecret('secret', 'secrez')).toBe(false);
        expect(equalsSecret('secret', 'secret-plus-long')).toBe(false);
    });
});
