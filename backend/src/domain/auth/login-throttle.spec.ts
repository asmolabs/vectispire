import { MAX_ATTEMPTS_PER_CLIENT, MAX_ATTEMPTS_PER_USER, WINDOW_MS, clientKey, decide, userKey, withinWindow } from './login-throttle';

const NOW = 1_800_000_000_000;
const attempts = (count: number, at = NOW) => Array.from({ length: count }, () => at);

describe('limitation des tentatives', () => {
    it('laisse passer en dessous des deux seuils', () => {
        expect(decide({ user: attempts(4), client: attempts(19) }, NOW)).toEqual({ allowed: true, retryAfterSeconds: 0 });
    });

    it('bloque au seuil utilisateur', () => {
        // Sans ce compteur, un attaquant réparti sur plusieurs machines essaierait
        // autant de mots de passe qu'il veut sur un même compte.
        const decision = decide({ user: attempts(MAX_ATTEMPTS_PER_USER), client: [] }, NOW);
        expect(decision.allowed).toBe(false);
        expect(decision.retryAfterSeconds).toBe(WINDOW_MS / 1000);
    });

    it('bloque au seuil client', () => {
        // Sans ce compteur-là, un attaquant essaierait cinq mots de passe par compte
        // sur toute la liste des utilisateurs.
        expect(decide({ user: [], client: attempts(MAX_ATTEMPTS_PER_CLIENT) }, NOW).allowed).toBe(false);
    });

    it('a un seuil client plus élevé, parce qu’un poste peut être partagé', () => {
        expect(MAX_ATTEMPTS_PER_CLIENT).toBeGreaterThan(MAX_ATTEMPTS_PER_USER);
    });

    it('annonce le délai du compteur le plus contraignant', () => {
        const decision = decide({ user: attempts(MAX_ATTEMPTS_PER_USER, NOW - 60_000), client: attempts(MAX_ATTEMPTS_PER_CLIENT, NOW) }, NOW);
        expect(decision.retryAfterSeconds).toBe(WINDOW_MS / 1000);
    });
});

describe('fenêtre glissante', () => {
    it('oublie les tentatives sorties de la fenêtre', () => {
        const old = attempts(MAX_ATTEMPTS_PER_USER, NOW - WINDOW_MS - 1);
        expect(decide({ user: old, client: [] }, NOW).allowed).toBe(true);
    });

    it('libère progressivement, sans pic au changement de fenêtre', () => {
        // Une fenêtre fixe offrirait à un attaquant un pic gratuit à heure ronde.
        const staggered = [NOW - WINDOW_MS - 1, NOW - 10_000, NOW - 9_000, NOW - 8_000, NOW - 7_000];
        expect(decide({ user: staggered, client: [] }, NOW).allowed).toBe(true);
    });

    it('calcule le délai depuis l’échec le plus ancien encore compté', () => {
        const decision = decide({ user: attempts(MAX_ATTEMPTS_PER_USER, NOW - WINDOW_MS + 30_000), client: [] }, NOW);
        expect(decision.retryAfterSeconds).toBe(30);
    });

    it('n’annonce jamais zéro seconde à un appelant bloqué', () => {
        // Annoncer « 0 » ferait retenter aussitôt et échouer à nouveau.
        const decision = decide({ user: attempts(MAX_ATTEMPTS_PER_USER, NOW - WINDOW_MS + 100), client: [] }, NOW);
        expect(decision.allowed).toBe(false);
        expect(decision.retryAfterSeconds).toBeGreaterThan(0);
    });

    it('filtre les tentatives à conserver', () => {
        expect(withinWindow([NOW - WINDOW_MS - 1, NOW - 1000, NOW], NOW)).toEqual([NOW - 1000, NOW]);
    });
});

describe('clés de comptage', () => {
    it('normalise l’identifiant utilisateur', () => {
        // Sinon « Alice », « alice » et « alice  » seraient trois compteurs, et le seuil
        // vaudrait trois fois plus pour qui varie la casse.
        expect(userKey('  Alice  ')).toBe(userKey('alice'));
        expect(userKey('ALICE')).toBe('login:user:alice');
    });

    it('sépare les deux espaces de noms', () => {
        expect(userKey('x')).not.toBe(clientKey('x'));
    });
});
