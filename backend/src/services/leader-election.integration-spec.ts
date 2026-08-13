import { DataSource, EntityManager } from 'typeorm';
import { LeaderLease } from '../persistence/entities';
import { LEASE_SECONDS, LeaderElectionService } from './leader-election.service';
import { connectToTestDatabase } from '../../test/database';

/**
 * L'élection de meneur, contre une vraie base.
 *
 * **Un test à doubles ne prouverait rien ici.** Toute la conception repose sur ce qu'un
 * `UPDATE` conditionnel fait réellement — combien de lignes il touche quand deux instances
 * se disputent la même ligne — et c'est précisément ce qu'un double simulerait au lieu de
 * le vérifier.
 *
 * Le cas qui compte est le vol de bail : une instance dont le bail court ne doit jamais se
 * le faire prendre, et une instance qui lit un bail expiré puis se le fait souffler entre
 * la lecture et l'écriture doit **perdre**, pas écraser le vainqueur.
 */

const JOB = 'test-scheduler';

describe('élection de meneur', () => {
    let dataSource: DataSource;
    let manager: EntityManager;
    let release: () => Promise<void>;

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

    function election(): LeaderElectionService {
        return new LeaderElectionService(manager);
    }

    const T0 = new Date('2026-08-13T10:00:00.000Z');
    const later = (seconds: number) => new Date(T0.getTime() + seconds * 1000);

    it('accorde le bail au premier arrivé', async () => {
        const service = election();

        expect(await service.acquire(JOB, 'instance-a', T0)).toBe(true);
        expect(await service.currentHolder(JOB, T0)).toBe('instance-a');
    });

    it('refuse le bail à une seconde instance tant que le premier court', async () => {
        const service = election();
        await service.acquire(JOB, 'instance-a', T0);

        expect(await service.acquire(JOB, 'instance-b', later(10))).toBe(false);
        expect(await service.currentHolder(JOB, later(10))).toBe('instance-a');
    });

    it('renouvelle sans changer de détenteur ni de date de prise', async () => {
        // Un meneur qui devrait reconquérir à chaque tour ferait tourner le travail dans
        // la flotte sans raison.
        const service = election();
        await service.acquire(JOB, 'instance-a', T0);

        expect(await service.acquire(JOB, 'instance-a', later(60))).toBe(true);

        const lease = await manager.findOneByOrFail(LeaderLease, { name: JOB });
        expect(lease.acquiredAt).toEqual(T0);
        expect(lease.expiresAt).toEqual(new Date(later(60).getTime() + LEASE_SECONDS * 1000));
    });

    it('remet le bail en jeu après expiration', async () => {
        // Un meneur mort doit être remplacé, sinon rien ne se passe plus jamais.
        const service = election();
        await service.acquire(JOB, 'instance-a', T0);

        expect(await service.currentHolder(JOB, later(LEASE_SECONDS + 1))).toBeNull();
        expect(await service.acquire(JOB, 'instance-b', later(LEASE_SECONDS + 1))).toBe(true);
        expect(await service.currentHolder(JOB, later(LEASE_SECONDS + 1))).toBe('instance-b');
    });

    it("ne vole pas un bail pris entre la lecture et l'écriture", async () => {
        // Le cas de course : deux instances lisent le même bail expiré, une gagne. La
        // perdante doit perdre — un UPDATE inconditionnel écraserait le vainqueur et les
        // deux se croiraient meneuses.
        const service = election();
        await service.acquire(JOB, 'instance-a', T0);
        const expired = later(LEASE_SECONDS + 1);

        const [first, second] = await Promise.all([
            service.acquire(JOB, 'instance-b', expired),
            service.acquire(JOB, 'instance-c', expired)
        ]);

        expect([first, second].filter(Boolean)).toHaveLength(1);
        const holder = await service.currentHolder(JOB, expired);
        expect(holder === 'instance-b' || holder === 'instance-c').toBe(true);
    });

    it('rend le bail à l\'arrêt, pour qu\'un successeur le prenne tout de suite', async () => {
        const service = election();
        await service.acquire(JOB, 'instance-a', T0);

        expect(await service.release(JOB, 'instance-a')).toBe(true);
        expect(await service.currentHolder(JOB, later(1))).toBeNull();
        expect(await service.acquire(JOB, 'instance-b', later(1))).toBe(true);
    });

    it("ne rend pas le bail d'un autre", async () => {
        const service = election();
        await service.acquire(JOB, 'instance-a', T0);

        expect(await service.release(JOB, 'instance-b')).toBe(false);
        expect(await service.currentHolder(JOB, later(1))).toBe('instance-a');
    });

    it('reprend un bail rendu, puis le tient à nouveau', async () => {
        // Le bail rendu porte `holder: null` : le chemin de réacquisition doit comparer
        // sur NULL et non par égalité, sinon plus personne ne peut jamais le reprendre.
        const service = election();
        await service.acquire(JOB, 'instance-a', T0);
        await service.release(JOB, 'instance-a');

        expect(await service.acquire(JOB, 'instance-b', later(1))).toBe(true);
        expect(await service.isLeader(JOB, 'instance-b', later(1))).toBe(true);
        expect(await service.isLeader(JOB, 'instance-a', later(1))).toBe(false);
    });
});
