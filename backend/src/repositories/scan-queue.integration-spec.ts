import { DataSource, EntityManager } from 'typeorm';
import { connectToTestDatabase } from '../../test/database';
import { now } from '../domain/common/timestamp';
import { MAX_ATTEMPTS } from '../domain/scans/queue-rules';
import { Repository as GitRepository, Scan, STATUS_FAILED, STATUS_QUEUED, STATUS_RUNNING } from '../persistence/entities';
import { ScanRepository } from './scan.repository';

/**
 * La file de scans, contre un vrai PostgreSQL.
 *
 * **Ces tests ne peuvent pas être unitaires.** Ce qu'ils vérifient — deux transactions
 * concurrentes ne réclament jamais la même ligne — est une propriété du moteur, pas du
 * code : `FOR UPDATE SKIP LOCKED` n'a pas d'équivalent simulable. Un faux dépôt en
 * mémoire passerait tous les cas et ne dirait rien.
 */
describe('file de scans', () => {
    let dataSource: DataSource;
    let manager: EntityManager;
    let release: () => Promise<void>;
    const scans = new ScanRepository();

    beforeAll(async () => {
        dataSource = await connectToTestDatabase();
    }, 30_000);

    beforeEach(async () => {
        const runner = dataSource.createQueryRunner();
        await runner.connect();
        await runner.startTransaction();
        manager = runner.manager;
        await manager.query('DELETE FROM t_scan');
        await manager.query('DELETE FROM t_repository');
        release = async () => {
            await runner.rollbackTransaction();
            await runner.release();
        };
    });

    afterEach(async () => release());

    async function seedRepository(manager_ = manager): Promise<GitRepository> {
        return manager_.save(GitRepository, Object.assign(new GitRepository(), { url: 'https://github.com/org/api.git', branch: 'main' }));
    }

    async function queue(repoId: number, count: number, manager_ = manager): Promise<Scan[]> {
        const created: Scan[] = [];
        for (let index = 0; index < count; index += 1) {
            created.push(
                await manager_.save(
                    Scan,
                    Object.assign(new Scan(), {
                        repoId,
                        branch: 'main',
                        status: STATUS_QUEUED,
                        // Des instants distincts et croissants : l'ordre de la file est
                        // l'ordre de création, et deux lignes du même instant le
                        // rendraient indéterminé.
                        createdAt: new Date(Date.now() + index)
                    })
                )
            );
        }
        return created;
    }

    it('réclame dans l’ordre de création', async () => {
        const repository = await seedRepository();
        const queued = await queue(repository.id, 3);

        const claimed = await scans.claim(manager, 2, 'worker-a');

        expect(claimed.map((scan) => scan.id)).toEqual([queued[0].id, queued[1].id]);
    });

    it('marque le scan réclamé, avec son propriétaire et son bail', async () => {
        const repository = await seedRepository();
        await queue(repository.id, 1);

        const [claimed] = await scans.claim(manager, 1, 'worker-a');

        expect(claimed.status).toBe(STATUS_RUNNING);
        expect(claimed.claimedBy).toBe('worker-a');
        expect(claimed.leaseExpiresAt!.getTime()).toBeGreaterThan(Date.now());
        // Le compteur de tentatives sert de garde-fou contre la reprise en boucle.
        expect(claimed.attempts).toBe(1);
    });

    it('ne rend rien quand la file est vide', async () => {
        expect(await scans.claim(manager, 5, 'worker-a')).toEqual([]);
    });

    it('ne rend rien quand la capacité est nulle', async () => {
        const repository = await seedRepository();
        await queue(repository.id, 3);
        expect(await scans.claim(manager, 0, 'worker-a')).toEqual([]);
    });

    describe('expiration des baux', () => {
        it('rend à la file un scan dont le bail a lapsé', async () => {
            const repository = await seedRepository();
            const [scan] = await queue(repository.id, 1);
            await scans.claim(manager, 1, 'worker-disparu');
            await manager.update(Scan, { id: scan.id }, { leaseExpiresAt: new Date('2020-01-01T00:00:00Z') });

            const { requeued, failed } = await scans.reclaimExpiredLeases(manager);

            expect(requeued.map((s) => s.id)).toEqual([scan.id]);
            expect(failed).toEqual([]);
            const reloaded = await manager.findOneByOrFail(Scan, { id: scan.id });
            expect(reloaded.status).toBe(STATUS_QUEUED);
            // Le bail tombe : sinon la reprise suivante le trouverait encore expiré.
            expect(reloaded.claimedBy).toBeNull();
            expect(reloaded.leaseExpiresAt).toBeNull();
        });

        it('rend à la file un scan « en cours » sans bail du tout', async () => {
            // L'état qu'on trouve après un arrêt brutal. Le laisser passer pour vivant le
            // rendrait irréclamable pour toujours.
            const repository = await seedRepository();
            const [scan] = await queue(repository.id, 1);
            await manager.update(Scan, { id: scan.id }, { status: STATUS_RUNNING, leaseExpiresAt: null });

            const { requeued } = await scans.reclaimExpiredLeases(manager);
            expect(requeued.map((s) => s.id)).toEqual([scan.id]);
        });

        it('ne touche pas un bail encore valable', async () => {
            const repository = await seedRepository();
            await queue(repository.id, 1);
            await scans.claim(manager, 1, 'worker-vivant');

            expect(await scans.reclaimExpiredLeases(manager)).toEqual({ requeued: [], failed: [] });
        });

        it('fait échouer un scan repris trop de fois, plutôt que de le laisser cycler', async () => {
            const repository = await seedRepository();
            const [scan] = await queue(repository.id, 1);
            await manager.update(Scan, { id: scan.id }, { status: STATUS_RUNNING, attempts: MAX_ATTEMPTS, leaseExpiresAt: new Date('2020-01-01T00:00:00Z') });

            const { requeued, failed } = await scans.reclaimExpiredLeases(manager);

            expect(requeued).toEqual([]);
            expect(failed.map((s) => s.id)).toEqual([scan.id]);
            const reloaded = await manager.findOneByOrFail(Scan, { id: scan.id });
            expect(reloaded.status).toBe(STATUS_FAILED);
            // Le message dit quoi regarder : sans lui, l'opérateur voit un échec sans cause.
            expect(reloaded.error).toMatch(/repris trop de fois/);
        });
    });

    describe('propriété', () => {
        it('reconnaît le travailleur qui détient le scan', async () => {
            const repository = await seedRepository();
            await queue(repository.id, 1);
            const [scan] = await scans.claim(manager, 1, 'worker-a');

            expect(await scans.stillOwned(manager, scan.id, 'worker-a')).toBe(true);
            // Un travailleur dont le bail a été repris ne doit pas écraser le travail de
            // son successeur en rendant des résultats périmés.
            expect(await scans.stillOwned(manager, scan.id, 'worker-b')).toBe(false);
        });

        it('refuse un scan qui n’est plus en cours', async () => {
            const repository = await seedRepository();
            await queue(repository.id, 1);
            const [scan] = await scans.claim(manager, 1, 'worker-a');
            await manager.update(Scan, { id: scan.id }, { status: STATUS_FAILED });

            expect(await scans.stillOwned(manager, scan.id, 'worker-a')).toBe(false);
        });

        it('prolonge le bail d’un scan qui progresse', async () => {
            const repository = await seedRepository();
            await queue(repository.id, 1);
            const [scan] = await scans.claim(manager, 1, 'worker-a');
            const before = scan.leaseExpiresAt!.getTime();

            await new Promise((resolve) => setTimeout(resolve, 5));
            expect(await scans.renewLease(manager, scan.id, 'worker-a')).toBe(true);

            const reloaded = await manager.findOneByOrFail(Scan, { id: scan.id });
            expect(reloaded.leaseExpiresAt!.getTime()).toBeGreaterThan(before);
        });

        it('refuse de prolonger le bail d’un autre', async () => {
            const repository = await seedRepository();
            await queue(repository.id, 1);
            const [scan] = await scans.claim(manager, 1, 'worker-a');

            expect(await scans.renewLease(manager, scan.id, 'worker-b')).toBe(false);
        });
    });
});
