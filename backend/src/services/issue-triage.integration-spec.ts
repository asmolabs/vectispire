import { DataSource, EntityManager } from 'typeorm';
import { InvalidTriageError } from '../domain/issues/triage';
import { ENTITIES, Issue, Repository, TRIAGE_NOT_AFFECTED, TRIAGE_UNDER_REVIEW } from '../persistence/entities';
import { IssueRepository } from '../repositories/issue.repository';
import { IssueTriageService } from './issue-triage.service';

const connectionString = process.env.ZANSHIN_TEST_DATABASE_URL;
const describeWithPostgres = connectionString ? describe : describe.skip;

describeWithPostgres('triage et backlog', () => {
    let dataSource: DataSource;
    let manager: EntityManager;
    let release: () => Promise<void>;
    const service = new IssueTriageService();
    const issues = new IssueRepository();

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
        release = async () => {
            await runner.rollbackTransaction();
            await runner.release();
        };
    });

    afterEach(async () => release());

    let counter = 0;

    async function repo(): Promise<number> {
        const saved = await manager.save(
            Object.assign(new Repository(), { url: `git@x:o/p-${(counter += 1)}.git`, branch: 'main', subPath: null, name: null, scanIntervalMinutes: null, scanCron: null, lastScheduledScanAt: null, sshKeyId: null })
        );
        return saved.id;
    }

    async function issue(repoId: number, over: Partial<Issue> = {}): Promise<Issue> {
        counter += 1;
        return manager.save(
            Object.assign(new Issue(), {
                repoId,
                containerId: null,
                fingerprint: `fp-${counter}-${Math.random()}`,
                type: 'vulnerability',
                identifier: `CVE-2024-${1000 + counter}`,
                packageName: 'requests',
                packageVersion: '2.31.0',
                purl: 'pkg:pypi/requests@2.31.0',
                filePath: 'requirements.txt',
                source: 'grype',
                severity: 'high',
                epssScore: null,
                isKev: false,
                cvssScore: null,
                cvssVector: null,
                fixState: null,
                fixVersions: null,
                link: null,
                description: null,
                state: 'open',
                firstSeenAt: new Date('2026-01-01T00:00:00Z'),
                lastSeenAt: new Date('2026-08-01T00:00:00Z'),
                resolvedAt: null,
                firstSeenScanId: null,
                lastSeenScanId: null,
                timesSeen: 1,
                triageStatus: TRIAGE_UNDER_REVIEW,
                triageJustification: null,
                triageComment: null,
                triagedBy: null,
                triagedAt: null,
                triageExpiresAt: null,
                isDirectDependency: null,
                line: null,
                ticketRef: null,
                ticketUrl: null,
                ...over
            })
        );
    }

    describe('enregistrement d’une décision', () => {
        it('écrit le statut, l’auteur et l’instant', async () => {
            const target = await issue(await repo());

            const triaged = await service.triage(manager, target.id, { status: TRIAGE_NOT_AFFECTED, actor: 'alice', justification: 'component_not_present' });

            expect(triaged.triageStatus).toBe(TRIAGE_NOT_AFFECTED);
            expect(triaged.triagedBy).toBe('alice');
            expect(triaged.triagedAt).not.toBeNull();
        });

        it('pose une échéance quand on la demande', async () => {
            const target = await issue(await repo());
            const triaged = await service.triage(manager, target.id, { status: TRIAGE_NOT_AFFECTED, actor: 'a', justification: 'component_not_present', expiresInDays: 30 });
            expect(triaged.triageExpiresAt).not.toBeNull();
        });

        it('refuse un « not_affected » sans justification, avant de toucher la base', async () => {
            // Validé avant le chargement : une demande mal formée ne doit pas coûter une
            // requête, et le message ne dépend pas de l'existence de la cible.
            await expect(service.triage(manager, 999_999, { status: TRIAGE_NOT_AFFECTED, actor: 'a' })).rejects.toThrow(/justification est requise/);
        });

        it('signale un problème introuvable', async () => {
            await expect(service.triage(manager, 999_999, { status: 'affected', actor: 'a' })).rejects.toBeInstanceOf(InvalidTriageError);
        });
    });

    describe('expiration des décisions', () => {
        it('ramène sous revue une décision échue, en gardant sa justification', async () => {
            const target = await issue(await repo(), {
                triageStatus: TRIAGE_NOT_AFFECTED,
                triageJustification: 'component_not_present',
                triageComment: 'Module absent en production.',
                triagedBy: 'alice',
                triageExpiresAt: new Date('2020-01-01T00:00:00Z')
            });

            const expired = await service.expireStale(manager);

            expect(expired).toHaveLength(1);
            const stored = await manager.findOneByOrFail(Issue, { id: target.id });
            expect(stored.triageStatus).toBe(TRIAGE_UNDER_REVIEW);
            expect(stored.triageExpiresAt).toBeNull();
            // Effacer le texte transformerait un réexamen programmé en enquête repartie
            // de zéro.
            expect(stored.triageJustification).toBe('component_not_present');
            expect(stored.triagedBy).toBe('alice');
        });

        it('laisse tranquille une décision dont l’échéance est à venir', async () => {
            await issue(await repo(), { triageStatus: TRIAGE_NOT_AFFECTED, triageJustification: 'component_not_present', triageExpiresAt: new Date('2099-01-01T00:00:00Z') });
            expect(await service.expireStale(manager)).toHaveLength(0);
        });
    });

    describe('backlog filtré', () => {
        it('classe les plus graves en premier, et non par ordre alphabétique', async () => {
            // « critical » viendrait après « high », et « low » avant « medium ».
            const repoId = await repo();
            for (const severity of ['low', 'critical', 'medium', 'high']) await issue(repoId, { severity });

            const page = await issues.findFiltered(manager, { repoId }, { limit: 10, offset: 0 });

            expect(page.map((row) => row.severity)).toEqual(['critical', 'high', 'medium', 'low']);
        });

        it('compte avec les mêmes filtres que la page', async () => {
            const repoId = await repo();
            for (let i = 0; i < 5; i += 1) await issue(repoId, { severity: i < 2 ? 'critical' : 'low' });

            const filters = { repoId, severity: 'critical' };
            expect(await issues.countFiltered(manager, filters)).toBe(2);
            expect(await issues.findFiltered(manager, filters, { limit: 10, offset: 0 })).toHaveLength(2);
        });

        it('pagine sans perdre ni répéter', async () => {
            const repoId = await repo();
            for (let i = 0; i < 5; i += 1) await issue(repoId);

            const first = await issues.findFiltered(manager, { repoId }, { limit: 2, offset: 0 });
            const second = await issues.findFiltered(manager, { repoId }, { limit: 2, offset: 2 });

            expect(new Set([...first, ...second].map((row) => row.id)).size).toBe(4);
        });

        it('ne cache pas les problèmes dont la nature de dépendance est inconnue', async () => {
            // « ne montre que les directes » est une demande ; « montre aussi les
            // transitives » est le défaut. Filtrer sur `false` cacherait les `null`,
            // les plus nombreux sur un dépôt sans graphe de dépendances.
            const repoId = await repo();
            await issue(repoId, { isDirectDependency: null });
            await issue(repoId, { isDirectDependency: true });

            expect(await issues.countFiltered(manager, { repoId })).toBe(2);
            expect(await issues.countFiltered(manager, { repoId, onlyDirect: true })).toBe(1);
        });

        it('cherche dans l’identifiant, le paquet et le chemin', async () => {
            const repoId = await repo();
            await issue(repoId, { identifier: 'CVE-2024-7777', packageName: 'lodash', filePath: 'package.json' });

            expect(await issues.countFiltered(manager, { repoId, search: '7777' })).toBe(1);
            expect(await issues.countFiltered(manager, { repoId, search: 'LODASH' })).toBe(1);
            expect(await issues.countFiltered(manager, { repoId, search: 'package.json' })).toBe(1);
            expect(await issues.countFiltered(manager, { repoId, search: 'introuvable' })).toBe(0);
        });
    });
});
