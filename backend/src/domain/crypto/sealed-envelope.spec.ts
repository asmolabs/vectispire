import { generateKeyPairSync } from 'node:crypto';
import { ENVELOPE_PREFIX, generateEphemeralKeyPair, isSealed, isUsablePublicKey, open, seal } from './sealed-envelope';

/**
 * L'enveloppe scellée, éprouvée sur ses échecs autant que sur son cas nominal.
 *
 * Un module de chiffrement dont on ne teste que le cas qui marche ne prouve rien : le
 * scellement le plus dangereux est celui qui *paraît* fonctionner — une enveloppe qui
 * s'ouvre pour le mauvais destinataire, ou dont on peut modifier le contenu sans que
 * l'ouverture échoue.
 */
describe('enveloppe scellée', () => {
    const SECRET = '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----\n';

    it('rend au destinataire exactement ce qui a été scellé', () => {
        const agent = generateEphemeralKeyPair();

        expect(open(agent, seal(agent.publicKey, SECRET))).toBe(SECRET);
    });

    it("ne s'ouvre pas avec la clé d'un autre destinataire", () => {
        // Le point de toute la construction : sans cela, n'importe quel agent enregistré
        // ouvrirait les enveloppes destinées aux autres.
        const destinataire = generateEphemeralKeyPair();
        const autre = generateEphemeralKeyPair();

        expect(open(autre, seal(destinataire.publicKey, SECRET))).toBeNull();
    });

    it('refuse une enveloppe dont le contenu a été modifié', () => {
        const agent = generateEphemeralKeyPair();
        const envelope = seal(agent.publicKey, SECRET);

        // Un octet retourné au milieu du chiffré. AES-GCM authentifie : l'ouverture doit
        // échouer, et non rendre un texte abîmé qu'un agent écrirait dans un fichier de clé.
        const raw = Buffer.from(envelope.slice(ENVELOPE_PREFIX.length), 'base64');
        raw[Math.floor(raw.length / 2)] ^= 0x01;

        expect(open(agent, ENVELOPE_PREFIX + raw.toString('base64'))).toBeNull();
    });

    it('refuse une enveloppe dont la clé éphémère a été remplacée', () => {
        // C'est ce que couvrent les données associées. Sans elles, substituer la clé
        // publique de l'expéditeur donnerait une autre dérivation au lieu d'un rejet.
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

    it('produit deux enveloppes différentes pour le même secret', () => {
        // Paire éphémère par enveloppe : deux scans du même dépôt ne doivent pas produire
        // le même chiffré, sans quoi une écoute apprendrait qu'il s'agit du même secret.
        const agent = generateEphemeralKeyPair();

        expect(seal(agent.publicKey, SECRET)).not.toBe(seal(agent.publicKey, SECRET));
    });

    it('lève plutôt que de rendre le secret en clair sur une clé illisible', () => {
        // **Refuser est le comportement correct.** Retomber sur le clair « parce que le
        // scellement a échoué » annulerait silencieusement toute la protection, et
        // l'opérateur ne verrait aucune différence.
        expect(() => seal('pas-une-clé', SECRET)).toThrow();
    });

    it('reconnaît une enveloppe et ne confond pas un secret en clair avec elle', () => {
        const agent = generateEphemeralKeyPair();

        expect(isSealed(seal(agent.publicKey, SECRET))).toBe(true);
        expect(isSealed(SECRET)).toBe(false);
        expect(isSealed(null)).toBe(false);
    });

    it('rend null sur ce qui n’est pas une enveloppe, sans lever', () => {
        // L'appelant est un agent qui traite l'échec comme « je n'ai pas reçu la clé » ;
        // une exception le ferait planter sur une valeur qu'il n'a pas choisie.
        const agent = generateEphemeralKeyPair();

        expect(open(agent, SECRET)).toBeNull();
        expect(open(agent, ENVELOPE_PREFIX + 'pas-du-base64-valide!!')).toBeNull();
        expect(open(agent, ENVELOPE_PREFIX)).toBeNull();
    });

    it('juge une clé publique avant qu’on tente de sceller pour elle', () => {
        expect(isUsablePublicKey(generateEphemeralKeyPair().publicKey)).toBe(true);
        expect(isUsablePublicKey('')).toBe(false);
        expect(isUsablePublicKey(null)).toBe(false);
        expect(isUsablePublicKey('bm9uLXVuZS1jbGU=')).toBe(false);
        // Une clé RSA est lisible mais ne convient pas à un échange X25519 : la rejeter
        // ici évite une exception au milieu d'une réclamation.
        const rsa = generateKeyPairSync('rsa', {
            modulusLength: 2048
        }).publicKey.export({ type: 'spki', format: 'der' });
        expect(isUsablePublicKey(rsa.toString('base64'))).toBe(false);
    });

    it('donne une paire différente à chaque agent qui démarre', () => {
        // Aucun fichier de clé à protéger, tourner ou oublier : un agent redémarré est un
        // nouveau destinataire.
        expect(generateEphemeralKeyPair().publicKey).not.toBe(generateEphemeralKeyPair().publicKey);
    });
});
