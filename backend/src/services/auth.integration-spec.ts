import { randomUUID } from 'node:crypto';
import { DataSource, EntityManager } from 'typeorm';
import { MAX_ATTEMPTS_PER_USER, WINDOW_MS } from '../domain/auth/login-throttle';
import { now } from '../domain/common/timestamp';
import { ENTITIES, LoginAttempt, Session, User } from '../persistence/entities';
import { AuthService } from './auth.service';
import { SessionCleanupService } from './session-cleanup.service';
import { hashPassword } from './password.service';
import { connectToTestDatabase } from '../../test/database';

/**
 * L'authentification contre une vraie base.
 *
 * Ce qui peut casser ici — un compte qui ne se verrouille pas, une session qui survit à
 * sa révocation, un compteur qui ne se vide pas après une connexion réussie — ne se voit
 * que dans les lignes qui restent.
 */

describe('authentification', () => {
    let dataSource: DataSource;
    let manager: EntityManager;
    let release: () => Promise<void>;
    const service = new AuthService();

    beforeAll(async () => {
        dataSource = await connectToTestDatabase();
    }, 30_000);

    beforeEach(async () => {
        const runner = dataSource.createQueryRunner();
        await runner.connect();
        await runner.startTransaction();
        manager = runner.manager;
        release = async () => {
            await runner.rollbackTransaction();
            await runner.release();
        };
    });

    afterEach(async () => release());

    async function account(over: Partial<User> = {}): Promise<User> {
        return manager.save(
            Object.assign(new User(), {
                username: `alice-${Math.trunc(Math.random() * 1e9)}`,
                email: null,
                password: hashPassword('bon-mot-de-passe'),
                displayName: null,
                avatarUrl: null,
                role: 'ADMIN',
                isActive: true,
                githubId: null,
                keycloakId: null,
                createdAt: new Date('2026-01-01T00:00:00Z'),
                updatedAt: new Date('2026-01-01T00:00:00Z'),
                mustChangePassword: false,
                ...over
            })
        );
    }

    const request = (user: User, over = {}) => ({ username: user.username, password: 'bon-mot-de-passe', clientId: 'poste-42', ...over });

    describe('connexion', () => {
        it('ouvre une session sur un mot de passe correct', async () => {
            const user = await account();
            const { outcome, audit } = await service.login(manager, request(user));

            expect(outcome.kind).toBe('success');
            expect(audit.operationType).toBe('LOGIN_SUCCESS');
            expect(await manager.countBy(Session, { userId: user.id })).toBe(1);
        });

        it('refuse un mot de passe faux, et compte l’échec', async () => {
            const user = await account();
            const { outcome, audit } = await service.login(manager, request(user, { password: 'faux' }));

            expect(outcome.kind).toBe('invalid');
            expect(audit.operationType).toBe('LOGIN_FAILURE');
            // Deux lignes : le compteur utilisateur et le compteur client.
            expect(await manager.countBy(LoginAttempt, {})).toBe(2);
        });

        it('refuse un compte désactivé', async () => {
            const user = await account({ isActive: false });
            expect((await service.login(manager, request(user))).outcome.kind).toBe('invalid');
        });

        it('refuse un identifiant inconnu sans révéler qu’il est inconnu', async () => {
            const { outcome, audit } = await service.login(manager, { username: 'personne', password: 'x', clientId: 'poste-42' });
            expect(outcome.kind).toBe('invalid');
            // Le message d'audit ne dit pas si le compte existe : une réponse trop
            // précise finit par fuiter dans un message d'erreur.
            expect(audit.description).toBe('Échec de connexion');
        });

        it('efface les compteurs après une connexion réussie', async () => {
            const user = await account();
            await service.login(manager, request(user, { password: 'faux' }));
            await service.login(manager, request(user));

            expect(await manager.countBy(LoginAttempt, {})).toBe(0);
        });
    });

    describe('verrouillage', () => {
        it('bloque après le seuil, et annonce un délai', async () => {
            const user = await account();
            for (let i = 0; i < MAX_ATTEMPTS_PER_USER; i += 1) {
                await service.login(manager, request(user, { password: 'faux' }));
            }

            const { outcome, audit } = await service.login(manager, request(user));

            // Bloqué **même avec le bon mot de passe** : le limiteur passe avant toute
            // comparaison, sinon il devient lui-même un levier de déni de service.
            expect(outcome.kind).toBe('blocked');
            if (outcome.kind === 'blocked') expect(outcome.retryAfterSeconds).toBeGreaterThan(0);
            expect(audit.operationType).toBe('LOGIN_BLOCKED');
        });

        it('n’ouvre aucune session quand il bloque', async () => {
            const user = await account();
            for (let i = 0; i < MAX_ATTEMPTS_PER_USER; i += 1) {
                await service.login(manager, request(user, { password: 'faux' }));
            }
            await service.login(manager, request(user));

            expect(await manager.countBy(Session, { userId: user.id })).toBe(0);
        });

        it('ne verrouille pas un autre compte depuis le même poste', async () => {
            // Le seuil client est plus élevé, précisément pour qu'un poste partagé ne
            // punisse pas le collègue suivant.
            const first = await account();
            const second = await account();
            for (let i = 0; i < MAX_ATTEMPTS_PER_USER; i += 1) {
                await service.login(manager, request(first, { password: 'faux' }));
            }

            expect((await service.login(manager, request(second))).outcome.kind).toBe('success');
        });
    });

    describe('résolution et révocation', () => {
        async function loggedIn() {
            const user = await account();
            const { outcome } = await service.login(manager, request(user));
            if (outcome.kind !== 'success') throw new Error('connexion attendue');
            return { user, token: outcome.session.token };
        }

        it('résout un jeton valide', async () => {
            const { token, user } = await loggedIn();
            const resolved = await service.resolve(manager, `Bearer ${token}`);
            expect(resolved?.userId).toBe(user.id);
        });

        it('rafraîchit l’horodatage d’activité', async () => {
            const { token } = await loggedIn();
            const before = (await manager.findOneByOrFail(Session, { token })).lastSeenAt;
            await new Promise((resolve) => setTimeout(resolve, 5));

            await service.resolve(manager, `Bearer ${token}`);

            expect((await manager.findOneByOrFail(Session, { token })).lastSeenAt).not.toBe(before);
        });

        it('déconnecte réellement — ce que Reflex ne pouvait pas faire', async () => {
            const { token } = await loggedIn();
            await service.revoke(manager, token);

            expect(await service.resolve(manager, `Bearer ${token}`)).toBeNull();
            expect(await manager.countBy(Session, { token })).toBe(0);
        });

        it('ferme toutes les sessions d’un compte', async () => {
            const user = await account();
            await service.login(manager, request(user));
            await service.login(manager, request(user, { clientId: 'autre-poste' }));

            expect(await service.revokeAllForUser(manager, user.id)).toBe(2);
            expect(await manager.countBy(Session, { userId: user.id })).toBe(0);
        });

        it('supprime une session périmée au lieu de seulement la refuser', async () => {
            const { token } = await loggedIn();
            // Antidatée au-delà de la durée absolue.
            await manager.update(Session, { token }, { createdAt: new Date('2020-01-01T00:00:00Z'), lastSeenAt: new Date('2020-01-01T00:00:00Z') });

            expect(await service.resolve(manager, `Bearer ${token}`)).toBeNull();
            expect(await manager.countBy(Session, { token })).toBe(0);
        });

        it.each([[null], [''], ['abc'], ['Bearer inconnu']])('rend null sur %p', async (header) => {
            expect(await service.resolve(manager, header as string | null)).toBeNull();
        });
    });
});

describe('purge des tables d’authentification', () => {
    let dataSource: DataSource;
    let manager: EntityManager;
    let release: () => Promise<void>;
    const cleanup = new SessionCleanupService();
    const auth = new AuthService();

    beforeAll(async () => {
        dataSource = await connectToTestDatabase();
    }, 30_000);

    beforeEach(async () => {
        const runner = dataSource.createQueryRunner();
        await runner.connect();
        await runner.startTransaction();
        manager = runner.manager;
        release = async () => {
            await runner.rollbackTransaction();
            await runner.release();
        };
    });

    afterEach(async () => release());

    async function user(): Promise<User> {
        return manager.save(
            Object.assign(new User(), {
                username: `bob-${Math.trunc(Math.random() * 1e9)}`,
                email: null,
                password: hashPassword('x'),
                displayName: null,
                avatarUrl: null,
                role: 'USER',
                isActive: true,
                githubId: null,
                keycloakId: null,
                createdAt: new Date('2026-01-01T00:00:00Z'),
                updatedAt: new Date('2026-01-01T00:00:00Z'),
                mustChangePassword: false
            })
        );
    }

    it('retire les sessions périmées et garde les vivantes', async () => {
        const account = await user();
        await auth.login(manager, { username: account.username, password: 'x', clientId: 'poste' });
        await manager.save(
            Object.assign(new Session(), {
                token: 'perimee',
                userId: account.id,
                createdAt: new Date('2020-01-01T00:00:00Z'),
                lastSeenAt: new Date('2020-01-01T00:00:00Z'),
                expiresAt: new Date('2020-01-02T00:00:00Z'),
                userAgent: null,
                ipAddress: null
            })
        );

        expect((await cleanup.prune(manager)).sessions).toBe(1);
        expect(await manager.countBy(Session, { userId: account.id })).toBe(1);
    });

    it('retire les tentatives sorties de la fenêtre de rétention', async () => {
        await manager.save(Object.assign(new LoginAttempt(), { id: randomUUID(), counterKey: 'login:user:vieux', occurredAt: new Date('2020-01-01T00:00:00Z') }));
        await manager.save(Object.assign(new LoginAttempt(), { id: randomUUID(), counterKey: 'login:user:recent', occurredAt: now() }));

        expect((await cleanup.prune(manager)).attempts).toBe(1);
        expect(await manager.countBy(LoginAttempt, { counterKey: 'login:user:recent' })).toBe(1);
    });

    it('garde les tentatives deux fois la fenêtre, pas une', async () => {
        // Couper au ras du seuil abaisserait un compteur qu'un comptage en cours est
        // peut-être en train de lire — donc ouvrirait une fenêtre à qui essaie des mots
        // de passe.
        // Un `Date`, pas une chaîne sans fuseau : sur une colonne `timestamptz`, une
        // chaîne naïve est interprétée dans le fuseau de la session, et l'instant écrit
        // n'est plus celui qu'on croyait poser. C'est précisément l'ambiguïté que le
        // passage à `timestamptz` supprime.
        const justPastWindow = new Date(Date.now() - WINDOW_MS - 60_000);
        await manager.save(Object.assign(new LoginAttempt(), { id: randomUUID(), counterKey: 'login:user:limite', occurredAt: justPastWindow }));

        await cleanup.prune(manager);

        expect(await manager.countBy(LoginAttempt, { counterKey: 'login:user:limite' })).toBe(1);
    });

    it('ne lève jamais, même sur une base qui refuse', async () => {
        const broken = { deleteExpired: async () => { throw new Error('table absente'); }, deleteBefore: async () => { throw new Error('table absente'); } };
        const fragile = new SessionCleanupService(broken as never, broken as never);
        await expect(fragile.prune(manager)).resolves.toEqual({ sessions: 0, attempts: 0 });
    });
});
