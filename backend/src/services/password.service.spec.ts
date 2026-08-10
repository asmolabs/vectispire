import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { BCRYPT_COST, hashPassword, verifyPassword } from './password.service';

interface BcryptVector {
    password: string;
    /** Produite par `bcrypt.hashpw(password.encode("utf-8")[:72], bcrypt.gensalt())`. */
    hash: string;
}

const pythonHashes: BcryptVector[] = JSON.parse(readFileSync(join(__dirname, '../../test/vectors/bcrypt-python.json'), 'utf8'));

describe('interopérabilité avec les empreintes écrites par Python', () => {
    it('dispose de vecteurs', () => {
        expect(pythonHashes.length).toBeGreaterThan(0);
    });

    // C'est ce qui décide si la migration réinitialise ou non les mots de passe de
    // tout le monde.
    it.each(pythonHashes)('vérifie l’empreinte de « $password »', ({ password, hash }) => {
        expect(verifyPassword(password, hash)).toBe(true);
    });

    it('refuse un mot de passe qui ne correspond pas', () => {
        expect(verifyPassword('autre chose', pythonHashes[0].hash)).toBe(false);
    });

    it('lit bien des empreintes de coût 12', () => {
        // Si Python avait écrit du coût 10, le défaut de bcryptjs passerait inaperçu.
        for (const { hash } of pythonHashes) expect(hash.startsWith(`$2b$${BCRYPT_COST}$`)).toBe(true);
    });
});

describe('troncature à 72 octets', () => {
    it('coupe en octets, et bcryptjs le fait déjà', () => {
        // « é » fait deux octets : 40 d'entre eux font 80 octets, donc la coupe tombe au
        // milieu du 37ᵉ caractère. C'est le cas qui départage — tronquer soi-même en
        // amont oblige à repasser par une chaîne, et l'encodage change les octets.
        const accented = 'é'.repeat(40);
        const vector = pythonHashes.find((item) => item.password === accented);
        expect(vector).toBeDefined();
        expect(verifyPassword(accented, vector!.hash)).toBe(true);
    });

    it("traite comme identiques deux mots de passe qui ne diffèrent qu'au-delà de 72 octets", () => {
        // La propriété de bcrypt elle-même, et la raison pour laquelle Python tronquait
        // explicitement : le geste était redondant, pas nécessaire.
        const hash = hashPassword('é'.repeat(36) + 'suffixe ignoré');
        expect(verifyPassword('é'.repeat(36) + 'tout autre suffixe', hash)).toBe(true);
    });

    it('ignore ce qui dépasse la limite, comme bcrypt lui-même', () => {
        const hash = hashPassword('x'.repeat(100));
        expect(verifyPassword('x'.repeat(72), hash)).toBe(true);
        expect(verifyPassword('x'.repeat(200), hash)).toBe(true);
    });

    it('laisse intact un mot de passe court', () => {
        const hash = hashPassword('court');
        expect(verifyPassword('court', hash)).toBe(true);
        expect(verifyPassword('courtt', hash)).toBe(false);
    });
});

describe('hachage', () => {
    it('produit une empreinte de coût 12', () => {
        expect(hashPassword('motdepasse').startsWith(`$2b$${BCRYPT_COST}$`)).toBe(true);
    });

    it('sale chaque empreinte', () => {
        expect(hashPassword('motdepasse')).not.toBe(hashPassword('motdepasse'));
    });
});

describe('vérification défensive', () => {
    it.each([[null], [undefined], [''], ['pas-une-empreinte'], ['$2b$12$trop-court']])('refuse sans lever sur %p', (hash) => {
        // Une ligne corrompue doit produire un refus, pas une erreur 500 sur l'écran de
        // connexion.
        expect(verifyPassword('motdepasse', hash as string | null | undefined)).toBe(false);
    });
});
