import { DataSource, EntityManager } from 'typeorm';
import { User } from '../persistence/entities';
import { BootstrapService } from './bootstrap.service';
import { verifyPassword } from './password.service';
import { connectToTestDatabase } from '../../test/database';

/**
 * L'amorçage du premier compte, contre une vraie base.
 *
 * **Ce chemin n'a pas de second essai.** Il ne s'exécute qu'une fois dans la vie d'une
 * installation, sur une table vide, et son échec est silencieux : l'opérateur le découvre
 * devant un écran de connexion qu'aucun identifiant ne franchit. C'est exactement le genre
 * de code qu'un test doit couvrir, parce que personne ne le réessaiera en développement.
 *
 * Il n'existait d'ailleurs pas — documenté dans trois fichiers, implémenté nulle part, et
 * trouvé en montant un plan de contrôle à la main pour éprouver l'agent distant.
 */
describe('amorçage du premier compte', () => {
    let dataSource: DataSource;
    let manager: EntityManager;
    let release: () => Promise<void>;
    const original = { ...process.env };

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

    afterEach(async () => {
        await release();
        process.env = { ...original };
    });

    function service(): BootstrapService {
        return new BootstrapService(manager);
    }

    function configure(username?: string, password?: string): void {
        if (username === undefined) delete process.env.ZANSHIN_BOOTSTRAP_USERNAME;
        else process.env.ZANSHIN_BOOTSTRAP_USERNAME = username;
        if (password === undefined) delete process.env.ZANSHIN_BOOTSTRAP_PASSWORD;
        else process.env.ZANSHIN_BOOTSTRAP_PASSWORD = password;
    }

    /** Un compte quelconque, pour occuper la table. */
    async function existingUser(): Promise<User> {
        const moment = new Date();
        return manager.save(
            Object.assign(new User(), {
                username: 'déjà-là',
                email: null,
                password: 'peu-importe',
                displayName: null,
                avatarUrl: null,
                role: 'ADMIN',
                isActive: true,
                githubId: null,
                keycloakId: null,
                createdAt: moment,
                updatedAt: moment,
                mustChangePassword: false
            })
        );
    }

    it('crée un SUPERUSER dont le mot de passe est vérifiable', async () => {
        configure('admin', 'motdepasse-solide');

        const created = await service().createFirstUser(manager);

        expect(created?.username).toBe('admin');
        expect(created?.role).toBe('SUPERUSER');
        expect(created?.isActive).toBe(true);
        // Haché, pas stocké en clair — et relisible par le même chemin que la connexion.
        expect(created?.password).not.toBe('motdepasse-solide');
        expect(verifyPassword('motdepasse-solide', created!.password)).toBe(true);
    });

    it('exige le changement du mot de passe à la première connexion', async () => {
        // Cette valeur transite par la configuration du déploiement, les journaux
        // d'orchestrateur et l'historique du shell. La laisser être le secret durable d'un
        // compte SUPERUSER serait le vrai défaut.
        configure('admin', 'motdepasse-solide');

        expect((await service().createFirstUser(manager))?.mustChangePassword).toBe(true);
    });

    it('ne fait rien quand un compte existe déjà', async () => {
        // **La condition qui empêche une porte dérobée.** Sans elle, poser la variable et
        // redémarrer recréerait un SUPERUSER à volonté, sur une installation en service.
        await existingUser();
        configure('intrus', 'motdepasse-solide');

        expect(await service().createFirstUser(manager)).toBeNull();
        expect(await manager.countBy(User, { username: 'intrus' })).toBe(0);
    });

    it('ne crée rien sans configuration, et le dit', async () => {
        configure(undefined, undefined);

        expect(await service().createFirstUser(manager)).toBeNull();
        expect(await manager.count(User)).toBe(0);
    });

    it('refuse un mot de passe trop court plutôt que de créer un compte faible', async () => {
        // Un premier compte est un SUPERUSER : il ouvre tout le reste.
        configure('admin', 'court');

        expect(await service().createFirstUser(manager)).toBeNull();
        expect(await manager.count(User)).toBe(0);
    });

    it("n'est pas dupé par un nom fait d'espaces", async () => {
        configure('   ', 'motdepasse-solide');

        expect(await service().createFirstUser(manager)).toBeNull();
    });

    it('est idempotent : deux appels ne créent qu\'un compte', async () => {
        // Le service tourne à chaque démarrage ; un redémarrage ne doit pas empiler les
        // comptes ni échouer sur une contrainte d'unicité.
        configure('admin', 'motdepasse-solide');

        await service().createFirstUser(manager);
        expect(await service().createFirstUser(manager)).toBeNull();
        expect(await manager.count(User)).toBe(1);
    });
});
