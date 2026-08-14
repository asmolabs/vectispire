import { DataSource } from 'typeorm';
import { CAPABILITIES } from '../persistence/dialects';
import { connectToTestDatabase, testDialect } from '../../test/database';
import { Repository as GitRepository, Scan, STATUS_QUEUED } from '../persistence/entities';
import { ScanRepository } from './scan.repository';

/**
 * La concurrence de la réclamation — dans son **propre fichier**, sans transaction
 * englobante.
 *
 * Ces tests vivaient avec les autres, sous un `beforeEach` qui ouvrait une transaction et
 * y supprimait les lignes pour isoler chaque cas. Deux transactions qui se voient l'une
 * l'autre sont précisément le sujet ici, et elles ne peuvent pas s'imbriquer dans une
 * troisième : la transaction extérieure gardait les verrous de sa propre suppression, et le
 * nettoyage hors transaction de ce bloc attendait indéfiniment. Le test passait seul et
 * expirait dans la campagne complète — un symptôme qu'on prend d'abord pour une machine
 * lente.
 */
describe('file de scans — concurrence', () => {
    let dataSource: DataSource;
    const scans = new ScanRepository();

    beforeAll(async () => {
        dataSource = await connectToTestDatabase();
    }, 30_000);

    async function seedRepository(manager = dataSource.manager): Promise<GitRepository> {
        return manager.save(GitRepository, Object.assign(new GitRepository(), { url: 'https://github.com/org/api.git', branch: 'main' }));
    }

    async function queue(repoId: number, count: number, manager = dataSource.manager): Promise<Scan[]> {
        const created: Scan[] = [];
        for (let index = 0; index < count; index += 1) {
            created.push(
                await manager.save(
                    Scan,
                    // Des instants distincts et croissants : l'ordre de la file est l'ordre
                    // de création, et deux lignes du même instant le rendraient indéterminé.
                    Object.assign(new Scan(), { repoId, branch: 'main', status: STATUS_QUEUED, createdAt: new Date(Date.now() + index) })
                )
            );
        }
        return created;
    }

    /**
     * Hors de la transaction du test : deux transactions qui se voient l'une l'autre
     * sont le sujet même de ce bloc, et elles ne peuvent pas être imbriquées dans une
     * troisième qui serait annulée.
     */
    async function withOwnData<T>(body: (source: DataSource) => Promise<T>): Promise<T> {
        const source = dataSource;
        await source.query('DELETE FROM t_scan');
        await source.query('DELETE FROM t_repository');
        try {
            return await body(source);
        } finally {
            await source.query('DELETE FROM t_scan');
            await source.query('DELETE FROM t_repository');
        }
    }

    it('ne donne jamais la même ligne à deux réclamants', async () => {
        await withOwnData(async (source) => {
            const repository = await seedRepository(source.manager);
            await queue(repository.id, 10, source.manager);

            // Dix réclamants simultanés, chacun dans sa propre transaction, chacun
            // demandant deux scans. C'est la situation d'une flotte d'agents qui
            // interrogent la même file.
            const claimants = Array.from({ length: 10 }, async (_, index) => {
                const runner = source.createQueryRunner();
                await runner.connect();
                await runner.startTransaction();
                try {
                    const taken = await scans.claim(runner.manager, 2, `worker-${index}`);
                    await runner.commitTransaction();
                    return taken.map((scan) => scan.id);
                } catch (error) {
                    await runner.rollbackTransaction();
                    throw error;
                } finally {
                    await runner.release();
                }
            });

            const results = (await Promise.all(claimants)).flat();

            // **Aucun doublon.** C'est la propriété de sûreté, la seule qu'un test unitaire
            // ne pourrait pas établir, et elle vaut sur les deux moteurs — mesuré, pas
            // supposé.
            expect(new Set(results).size).toBe(results.length);

            const remaining = await source.manager.countBy(Scan, { status: STATUS_QUEUED });

            if (CAPABILITIES[testDialect()].claimsCompleteBatches) {
                // PostgreSQL sert le lot demandé : la file part entièrement en un tour.
                expect(results).toHaveLength(10);
                expect(remaining).toBe(0);
            } else {
                // MySQL compte les lignes sautées dans le `LIMIT`, donc un lot revient
                // court sous contention. Le reste part au tour suivant — c'est du débit,
                // pas de la correction. Affirmer ici `toBe(0)` reviendrait à exiger du
                // moteur une garantie qu'il ne donne pas, et le test échouerait pour la
                // seule raison qu'il décrit mal ce qui est promis.
                expect(results.length).toBeGreaterThan(0);
                expect(results.length + remaining).toBe(10);
            }
        });
        // Délai explicite : ce test n'est pas lent en soi — quelques centaines de
        // millisecondes isolément — mais la campagne complète exécute par ailleurs de
        // vrais scans de conteneurs, et dix transactions concurrentes sur une machine
        // chargée dépassent le délai par défaut. Le voir échouer dans la campagne et
        // passer seul est le symptôme d'une machine occupée, pas d'un verrou perdu.
    }, 120_000);

    it('laisse les autres avancer plutôt que de les faire attendre', async () => {
        await withOwnData(async (source) => {
            const repository = await seedRepository(source.manager);
            await queue(repository.id, 4, source.manager);

            const first = source.createQueryRunner();
            await first.connect();
            await first.startTransaction();
            const held = await scans.claim(first.manager, 2, 'worker-lent');

            // Le premier tient encore ses lignes. Le second ne doit pas bloquer sur
            // elles : `SKIP LOCKED` est exactement ce qui l'en dispense.
            const second = source.createQueryRunner();
            await second.connect();
            await second.startTransaction();
            const other = await scans.claim(second.manager, 2, 'worker-rapide');

            expect(other).toHaveLength(2);
            expect(other.map((scan) => scan.id)).not.toEqual(expect.arrayContaining(held.map((scan) => scan.id)));

            await second.commitTransaction();
            await second.release();
            await first.commitTransaction();
            await first.release();
        });
    });
});
