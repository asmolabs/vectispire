import { DataSource, EntityManager } from 'typeorm';
import { now } from '../domain/common/timestamp';
import { ENTITIES, Issue, Repository as GitRepository, Scan, STATE_OPEN, STATE_RESOLVED, TRIAGE_AFFECTED } from '../persistence/entities';
import { DashboardController } from './dashboard.controller';
import { GateController } from './gate.controller';

const connectionString = process.env.ZANSHIN_TEST_DATABASE_URL;
const describeWithPostgres = connectionString ? describe : describe.skip;

describeWithPostgres('tableau de bord', () => {
    let dataSource: DataSource;
    let manager: EntityManager;
    let release: () => Promise<void>;
    let controller: DashboardController;

    beforeAll(async () => {
        dataSource = new DataSource({ type: 'postgres', url: connectionString, entities: ENTITIES, synchronize: false });
        await dataSource.initialize();
    }, 30_000);

    afterAll(async () => {
        if (dataSource?.isInitialized) await dataSource.destroy();
    });

    beforeEach(async () => {
        const runner = dataSource.createQueryRunner();
        await runner.connect();
        await runner.startTransaction();
        manager = runner.manager;
        controller = new DashboardController(manager);
        await manager.query('DELETE FROM issue');
        await manager.query('DELETE FROM scan');
        await manager.query('DELETE FROM repository');
        await manager.query('DELETE FROM container');
        release = async () => {
            await runner.rollbackTransaction();
            await runner.release();
        };
    });

    afterEach(async () => release());

    async function seedRepository(name: string): Promise<GitRepository> {
        return manager.save(GitRepository, Object.assign(new GitRepository(), { url: `https://github.com/org/${name}.git`, branch: 'main', name }));
    }

    /**
     * `triageStatus` par défaut à `affected` : avec `includeTriaged: false`, la politique
     * ne considère que les problèmes triés `under_review` ou `affected`. C'est la
     * sémantique de Python, vérifiée par les vecteurs de parité — un problème non trié ne
     * fait échouer aucune compilation tant que personne ne l'a regardé.
     */
    async function seedIssue(
        repoId: number,
        severity: string,
        type = 'vulnerability',
        state = STATE_OPEN,
        isKev = false,
        triageStatus = TRIAGE_AFFECTED
    ): Promise<void> {
        await manager.save(
            Issue,
            Object.assign(new Issue(), {
                repoId, fingerprint: `f-${repoId}-${severity}-${type}-${Math.round(performance.now() * 1000)}`,
                type, identifier: 'CVE-2026-0001', severity, state, isKev,
                firstSeenAt: now(), lastSeenAt: now(), timesSeen: 1, triageStatus
            })
        );
    }

    it('compte le backlog par sévérité, hors qualité', async () => {
        const repository = await seedRepository('api');
        await seedIssue(repository.id, 'critical');
        await seedIssue(repository.id, 'high');
        await seedIssue(repository.id, 'high');
        await seedIssue(repository.id, 'high', 'quality');
        await seedIssue(repository.id, 'low', 'vulnerability', STATE_RESOLVED);

        const result = await controller.overview();
        // Le constat de qualité et le problème résolu sont absents du compte.
        expect(result.backlogBySeverity).toEqual({ critical: 1, high: 2 });
        expect(result.qualityTotal).toBe(1);
    });

    it('rend une posture identique à celle de l’écran Sécurité', async () => {
        const repository = await seedRepository('api');
        await manager.save(Scan, Object.assign(new Scan(), { repoId: repository.id, branch: 'main', status: 'completed', findingsCount: 1, createdAt: now() }));
        await seedIssue(repository.id, 'critical');

        // Le tableau de bord est en page d'accueil : c'est son chiffre qu'on croit. S'il
        // divergeait de l'écran de détail, c'est le détail qu'on soupçonnerait.
        const dashboard = await controller.overview();
        const security = await new GateController(manager).overview();

        expect(dashboard.posture.failingCount).toBe(security.failingCount);
        expect(dashboard.posture.totalCount).toBe(security.totalCount);
        expect(dashboard.posture.kevCount).toBe(security.kevCount);
        expect(dashboard.posture.neverScannedCount).toBe(security.neverScannedCount);
    });

    it('compte à part les cibles jamais scannées', async () => {
        await seedRepository('jamais');
        const result = await controller.overview();
        // Leur backlog vide passe toutes les politiques : sans ce chiffre, elles
        // s'ajouteraient silencieusement aux cibles conformes.
        expect(result.posture.neverScannedCount).toBe(1);
    });

    it('liste les cibles en échec avec la règle en cause', async () => {
        const repository = await seedRepository('api');
        await manager.save(Scan, Object.assign(new Scan(), { repoId: repository.id, branch: 'main', status: 'completed', findingsCount: 1, createdAt: now() }));
        await seedIssue(repository.id, 'critical');

        const result = await controller.overview();
        expect(result.failing).toHaveLength(1);
        expect(result.failing[0].name).toBe('api');
        expect(result.failing[0].violations.length).toBeGreaterThan(0);
    });

    it('rend les scans récents avec leur erreur', async () => {
        const repository = await seedRepository('api');
        await manager.save(Scan, Object.assign(new Scan(), { repoId: repository.id, branch: 'main', status: 'failed', findingsCount: 0, error: 'clone refusé', createdAt: now() }));

        const result = await controller.overview();
        expect(result.recentScans).toHaveLength(1);
        expect(result.recentScans[0].error).toBe('clone refusé');
        // Un instant absolu : sérialisé en JSON, il porte son fuseau, et l'écran le rend
        // dans celui du lecteur. C'est ce que `timestamptz` a rendu possible.
        expect(result.recentScans[0].createdAt).toBeInstanceOf(Date);
    });

    it('rend des zéros et non une erreur sur une base vide', async () => {
        const result = await controller.overview();
        expect(result.posture).toEqual({ failingCount: 0, totalCount: 0, kevCount: 0, neverScannedCount: 0, lastScanFailedCount: 0 });
        expect(result.backlogBySeverity).toEqual({});
        expect(result.failing).toEqual([]);
    });
});
