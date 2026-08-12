import { execFile, spawn, type ChildProcess } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { DataSource } from 'typeorm';
import { connectToTestDatabase } from '../../test/database';
import { now } from '../domain/common/timestamp';
import { Issue, Repository as GitRepository, Scan, STATE_OPEN, STATUS_COMPLETED, STATUS_FAILED, STATUS_QUEUED } from '../persistence/entities';
import { ContainerRunner } from '../scanning/container-runner';
import { CHECKOV_IMAGE, GITLEAKS_IMAGE, GRYPE_IMAGE, SYFT_IMAGE } from '../scanning/scanners/images';
import { ScanDispatcherService } from './scan-dispatcher.service';

const run = promisify(execFile);
const AWS_KEY = 'AKIA' + 'Z6TJ4KQXPL2WMNBV';

/**
 * La chaîne complète : une ligne en file, un vrai scan, des problèmes en base.
 *
 * C'est le seul test qui traverse tout — réclamation, bail, clone, scanners, ingestion,
 * empreintes, résolution. Les tests précédents établissent chaque maillon ; celui-ci
 * établit qu'ils tiennent ensemble.
 */
describe('distribution des scans', () => {
    let dataSource: DataSource;
    let dispatcher: ScanDispatcherService;
    let origin: string;
    let scratch: string;
    let daemon: ChildProcess;
    const containers = new ContainerRunner();

    beforeAll(async () => {
        dataSource = await connectToTestDatabase();
        dispatcher = new ScanDispatcherService(dataSource);

        if (!(await containers.isAvailable())) {
            throw new Error('Le démon Docker est injoignable : ce test exerce la chaîne réelle.');
        }
        for (const image of [SYFT_IMAGE, GRYPE_IMAGE, GITLEAKS_IMAGE, CHECKOV_IMAGE]) {
            await new Promise<void>((resolve, reject) => {
                void containers['docker'].pull(image, (error: Error | null, stream: NodeJS.ReadableStream) => {
                    if (error) return reject(error);
                    containers['docker'].modem.followProgress(stream, (done: Error | null) => (done ? reject(done) : resolve()));
                });
            });
        }

        scratch = await mkdtemp(join(tmpdir(), 'zanshin-file-'));
        const bare = join(scratch, 'cible.git');
        await run('git', ['init', '--bare', '--initial-branch=main', bare]);
        const working = join(scratch, 'travail');
        await run('git', ['clone', bare, working]);
        await writeFile(join(working, 'config.py'), `CLE = "${AWS_KEY}"\n`);
        await run('git', ['-C', working, 'add', '.']);
        await run('git', ['-C', working, '-c', 'user.email=t@z', '-c', 'user.name=T', 'commit', '-m', 'cible']);
        await run('git', ['-C', working, 'push', 'origin', 'main']);

        const port = 10_600 + (process.pid % 300);
        daemon = spawn('git', ['daemon', `--base-path=${scratch}`, '--export-all', '--reuseaddr', `--port=${port}`, scratch], { stdio: 'ignore' });
        origin = `git://127.0.0.1:${port}/cible.git`;
        await new Promise((resolve) => setTimeout(resolve, 400));
    }, 900_000);

    afterAll(async () => {
        daemon?.kill();
        await rm(scratch, { recursive: true, force: true });
    });

    beforeEach(async () => {
        // Pas de transaction annulée ici : le distributeur ouvre les siennes, et les
        // imbriquer dans une transaction du test rendrait le comportement différent de
        // celui de la production — précisément ce que ce test existe pour vérifier.
        await dataSource.query('DELETE FROM t_issue');
        await dataSource.query('DELETE FROM t_finding');
        await dataSource.query('DELETE FROM t_scan');
        await dataSource.query('DELETE FROM t_repository');
    });

    async function queueScan(url = origin): Promise<{ repository: GitRepository; scan: Scan }> {
        const repository = await dataSource.manager.save(GitRepository, Object.assign(new GitRepository(), { url, branch: 'main' }));
        const scan = await dataSource.manager.save(
            Scan,
            Object.assign(new Scan(), { repoId: repository.id, branch: 'main', status: STATUS_QUEUED, createdAt: now() })
        );
        return { repository, scan };
    }

    it('mène un scan de la file jusqu’aux problèmes en base', async () => {
        const { repository, scan } = await queueScan();

        const result = await dispatcher.dispatch('worker-a', 2);

        expect(result).toEqual({ claimed: 1, completed: 1, failed: 0 });

        const finished = await dataSource.manager.findOneByOrFail(Scan, { id: scan.id });
        expect(finished.status).toBe(STATUS_COMPLETED);
        // Le bail est rendu : sans cela, la reprise suivante croirait le scan abandonné.
        expect(finished.claimedBy).toBeNull();
        expect(finished.leaseExpiresAt).toBeNull();
        expect(finished.durationMs).toBeGreaterThan(0);

        const issues = await dataSource.manager.findBy(Issue, { repoId: repository.id });
        expect(issues.length).toBeGreaterThan(0);
        expect(issues.some((issue) => issue.type === 'secret')).toBe(true);
        expect(issues.every((issue) => issue.state === STATE_OPEN)).toBe(true);
    }, 900_000);

    it('reconnaît le même problème d’un scan à l’autre au lieu de le dupliquer', async () => {
        const { repository } = await queueScan();
        await dispatcher.dispatch('worker-a', 2);
        const first = await dataSource.manager.findBy(Issue, { repoId: repository.id });

        // Un second scan de la même cible : l'empreinte doit reconnaître les problèmes.
        await dataSource.manager.save(
            Scan,
            Object.assign(new Scan(), { repoId: repository.id, branch: 'main', status: STATUS_QUEUED, createdAt: now() })
        );
        await dispatcher.dispatch('worker-a', 2);

        const second = await dataSource.manager.findBy(Issue, { repoId: repository.id });
        expect(second).toHaveLength(first.length);
        // C'est ce compteur qui distingue « revu » de « nouveau », et c'est lui qui
        // préserverait un triage posé entre les deux scans.
        expect(second.every((issue) => issue.timesSeen >= 2)).toBe(true);
    }, 900_000);

    it('marque le scan en échec et rend son bail quand le clone échoue', async () => {
        const { scan } = await queueScan('git://127.0.0.1:1/inexistant.git');

        const result = await dispatcher.dispatch('worker-a', 2);

        expect(result).toEqual({ claimed: 1, completed: 0, failed: 1 });
        const failed = await dataSource.manager.findOneByOrFail(Scan, { id: scan.id });
        expect(failed.status).toBe(STATUS_FAILED);
        expect(failed.error).toBeTruthy();
        // Le bail doit tomber : un scan en échec qui le garderait serait repris par la
        // reprise suivante, et échouerait à nouveau jusqu'à épuisement des tentatives.
        expect(failed.leaseExpiresAt).toBeNull();
    }, 900_000);

    it('ne réclame rien quand la capacité est déjà prise', async () => {
        await queueScan();
        // Un scan déjà en cours ailleurs occupe la seule place disponible.
        await dataSource.manager.save(
            Scan,
            Object.assign(new Scan(), { branch: 'main', status: 'scanning', createdAt: now(), claimedBy: 'autre', leaseExpiresAt: new Date(Date.now() + 600_000) })
        );

        expect(await dispatcher.dispatch('worker-a', 1)).toEqual({ claimed: 0, completed: 0, failed: 0 });
    }, 300_000);

    it('écarte les résultats d’un travailleur qui a perdu son bail', async () => {
        const { repository, scan } = await queueScan();

        // Le scan est réclamé par un autre pendant que le nôtre travaille : c'est la
        // situation d'un bail expiré puis repris. Écrire ici écraserait le travail du
        // successeur avec des résultats périmés.
        const stealing = dispatcher.dispatch('worker-a', 2);
        await new Promise((resolve) => setTimeout(resolve, 1500));
        await dataSource.manager.update(Scan, { id: scan.id }, { claimedBy: 'worker-b' });
        await stealing;

        const finished = await dataSource.manager.findOneByOrFail(Scan, { id: scan.id });
        expect(finished.status).not.toBe(STATUS_COMPLETED);
        expect(await dataSource.manager.countBy(Issue, { repoId: repository.id })).toBe(0);
    }, 900_000);
});
