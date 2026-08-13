import { DataSource, EntityManager } from 'typeorm';
import { Container, Repository as GitRepository, STATUS_QUEUED, STATUS_RUNNING, Scan } from '../persistence/entities';
import { LeaderElectionService } from './leader-election.service';
import { SchedulerService } from './scheduler.service';
import { connectToTestDatabase } from '../../test/database';

/**
 * L'ordonnanceur, contre une vraie base.
 *
 * Ce qui compte ici n'est pas la politique d'échéance — elle est pure et testée à part —
 * mais **l'ordre des écritures** : l'estampille avant la mise en file, le refus du
 * doublon, et le fait qu'un tour sans bail n'écrive rien du tout.
 *
 * **Chaque assertion porte sur la cible du test, jamais sur toute la table.** Un
 * `count(Scan)` global suppose une base vide, ce qu'aucune campagne ne garantit : une suite
 * non transactionnelle interrompue en cours — par un hoquet de Docker, par exemple —
 * laisse des lignes validées derrière elle, et le test échoue en accusant l'ordonnanceur
 * d'une écriture qu'il n'a pas faite.
 */

const T0 = new Date('2026-08-13T10:00:00.000Z');
const minutesAgo = (minutes: number) => new Date(T0.getTime() - minutes * 60_000);

describe('ordonnanceur', () => {
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

    function scheduler(): SchedulerService {
        return new SchedulerService(manager, new LeaderElectionService(manager));
    }

    async function repository(values: Partial<GitRepository> = {}): Promise<GitRepository> {
        return manager.save(
            Object.assign(new GitRepository(), {
                url: 'git@exemple:org/projet.git',
                branch: 'main',
                subPath: null,
                name: null,
                scanIntervalMinutes: 60,
                scanCron: null,
                lastScheduledScanAt: null,
                sshKeyId: null,
                ...values
            })
        );
    }

    it('met en file une cible due et estampille la date', async () => {
        const repo = await repository({ lastScheduledScanAt: minutesAgo(120) });

        expect(await scheduler().runOnce(T0)).toBe(1);

        const [scan] = await manager.find(Scan, { where: { repoId: repo.id } });
        expect(scan.status).toBe(STATUS_QUEUED);
        expect(scan.branch).toBe('main');
        expect((await manager.findOneByOrFail(GitRepository, { id: repo.id })).lastScheduledScanAt).toEqual(T0);
    });

    it('ne met rien en file pour une cible qui ne l\'est pas', async () => {
        const repo = await repository({ lastScheduledScanAt: minutesAgo(10) });

        expect(await scheduler().runOnce(T0)).toBe(0);
        expect(await manager.countBy(Scan, { repoId: repo.id })).toBe(0);
    });

    it("estampille même quand un scan est déjà en file, pour ne pas réexaminer à chaque tour", async () => {
        // Le piège de l'ordre : sans estampille, une cible dont le scan traîne serait
        // reconsidérée à chaque tour — soixante fois par heure pour rien.
        const repo = await repository({ lastScheduledScanAt: minutesAgo(120) });
        await manager.save(Object.assign(new Scan(), { repoId: repo.id, branch: 'main', status: STATUS_QUEUED, createdAt: minutesAgo(5) }));

        expect(await scheduler().runOnce(T0)).toBe(0);
        expect((await manager.findOneByOrFail(GitRepository, { id: repo.id })).lastScheduledScanAt).toEqual(T0);
        expect(await manager.countBy(Scan, { repoId: repo.id })).toBe(1);
    });

    it("met en file malgré un scan en cours, qui n'est pas en attente", async () => {
        // Le refus ne porte que sur la file : un scan qui tourne depuis une heure ne doit
        // pas empêcher indéfiniment le suivant.
        const repo = await repository({ lastScheduledScanAt: minutesAgo(120) });
        await manager.save(Object.assign(new Scan(), { repoId: repo.id, branch: 'main', status: STATUS_RUNNING, createdAt: minutesAgo(30) }));

        expect(await scheduler().runOnce(T0)).toBe(1);
    });

    it('honore une expression cron plutôt que son intervalle', async () => {
        await repository({ scanCron: '0 2 * * *', scanIntervalMinutes: 1, lastScheduledScanAt: new Date('2026-08-13T02:00:00.000Z') });

        expect(await scheduler().runOnce(T0)).toBe(0);
    });

    it('ordonnance aussi les conteneurs', async () => {
        const image = await manager.save(
            Object.assign(new Container(), {
                imageName: 'docker.io/library/nginx',
                tag: 'latest',
                digest: null,
                name: null,
                registryUrl: null,
                scanIntervalMinutes: 60,
                scanCron: null,
                lastScheduledScanAt: minutesAgo(120)
            })
        );

        expect(await scheduler().runOnce(T0)).toBe(1);
        expect(await manager.countBy(Scan, { containerId: image.id })).toBe(1);
    });

    it("n'écrit rien quand le bail appartient à quelqu'un d'autre", async () => {
        // Le point de toute l'élection : l'estampille avant envoi protège contre un
        // processus qui ticke deux fois, et pas du tout contre deux processus qui tickent
        // ensemble. Sans bail, chaque cible serait scannée autant de fois qu'il y a
        // d'instances.
        const repo = await repository({ lastScheduledScanAt: minutesAgo(120) });
        await new LeaderElectionService(manager).acquire('scheduler', 'une-autre-instance', T0);

        expect(await scheduler().runOnce(T0)).toBe(0);
        expect(await manager.countBy(Scan, { repoId: repo.id })).toBe(0);
        expect((await manager.findOneByOrFail(GitRepository, { id: repo.id })).lastScheduledScanAt).toEqual(minutesAgo(120));
    });

    it("saute le tour plutôt que de se croire seul quand le bail est inaccessible", async () => {
        // Échoue fermé : sauter un tour coûte une minute de latence, se croire meneur à
        // tort coûte un scan dupliqué de chaque cible due.
        const repo = await repository({ lastScheduledScanAt: minutesAgo(120) });
        const election = new LeaderElectionService(manager);
        election.acquire = async () => {
            throw new Error('base injoignable');
        };

        expect(await new SchedulerService(manager, election).runOnce(T0)).toBe(0);
        expect(await manager.countBy(Scan, { repoId: repo.id })).toBe(0);
    });
});
