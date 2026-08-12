import { execFile, spawn, type ChildProcess } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { ContainerRunner } from './container-runner';
import { ScanRunner } from './scan-runner';
import { CHECKOV_IMAGE, GITLEAKS_IMAGE, GRYPE_IMAGE, SEMGREP_IMAGE, SYFT_IMAGE } from './scanners/images';

const run = promisify(execFile);

/**
 * Le scan complet, de bout en bout : un vrai dépôt cloné, cinq vrais scanners, de vrais
 * constats.
 *
 * C'est le seul test qui établisse que la chaîne **entière** fonctionne. Chaque scanner a
 * le sien, mais aucun ne dit que le clone, la copie des règles, les montages et l'ordre
 * des étapes s'accordent — et c'est précisément là que vivent les erreurs d'assemblage.
 */
const AWS_KEY = 'AKIA' + 'Z6TJ4KQXPL2WMNBV';

describe('scan complet', () => {
    const containers = new ContainerRunner();
    const runner = new ScanRunner(containers);
    let origin: string;
    let scratch: string;
    let daemon: ChildProcess;

    beforeAll(async () => {
        if (!(await containers.isAvailable())) {
            throw new Error('Le démon Docker est injoignable : ce test exerce la chaîne réelle et ne peut pas être simulé.');
        }
        for (const image of [SYFT_IMAGE, GRYPE_IMAGE, GITLEAKS_IMAGE, CHECKOV_IMAGE, SEMGREP_IMAGE]) {
            await new Promise<void>((resolve, reject) => {
                void containers['docker'].pull(image, (error: Error | null, stream: NodeJS.ReadableStream) => {
                    if (error) return reject(error);
                    containers['docker'].modem.followProgress(stream, (done: Error | null) => (done ? reject(done) : resolve()));
                });
            });
        }

        scratch = await mkdtemp(join(tmpdir(), 'zanshin-cible-'));
        const bare = join(scratch, 'cible.git');
        await run('git', ['init', '--bare', '--initial-branch=main', bare]);

        const working = join(scratch, 'travail');
        await run('git', ['clone', bare, working]);
        // Une cible qui donne du grain à chacun des quatre scanners.
        await writeFile(join(working, 'package.json'), JSON.stringify({ name: 'cible', version: '1.0.0', dependencies: { lodash: '4.17.11' } }));
        await writeFile(
            join(working, 'package-lock.json'),
            JSON.stringify({
                name: 'cible',
                lockfileVersion: 2,
                packages: { '': { dependencies: { lodash: '4.17.11' } }, 'node_modules/lodash': { version: '4.17.11' } }
            })
        );
        await writeFile(join(working, 'config.py'), `CLE = "${AWS_KEY}"\n\ndef traite(entree):\n    return eval(entree)\n`);
        await writeFile(join(working, 'main.tf'), 'resource "aws_s3_bucket" "donnees" {\n  bucket = "zanshin-essai"\n}\n');
        await run('git', ['-C', working, 'add', '.']);
        await run('git', ['-C', working, '-c', 'user.email=t@zanshin', '-c', 'user.name=T', 'commit', '-m', 'cible']);
        await run('git', ['-C', working, 'push', 'origin', 'main']);

        const port = 10_000 + (process.pid % 500);
        daemon = spawn('git', ['daemon', `--base-path=${scratch}`, '--export-all', '--reuseaddr', `--port=${port}`, scratch], { stdio: 'ignore' });
        origin = `git://127.0.0.1:${port}/cible.git`;
        await new Promise((resolve) => setTimeout(resolve, 400));
    }, 900_000);

    afterAll(async () => {
        daemon?.kill();
        await rm(scratch, { recursive: true, force: true });
    });

    it('enchaîne clone et scanners, et rend les constats de chacun', async () => {
        const artifacts = await runner.run({ url: origin, branch: 'main', runSast: true });

        expect(artifacts.failures).toEqual([]);

        // Chaque étape a produit quelque chose : c'est l'assemblage qui est vérifié ici,
        // pas la justesse de chaque scanner — leurs propres tests s'en chargent.
        expect(artifacts.sbom).not.toBeNull();
        expect(artifacts.dependencies!.some((finding) => finding.packageName === 'lodash')).toBe(true);
        expect(artifacts.secrets!.some((finding) => finding.file === 'config.py')).toBe(true);
        expect(artifacts.iac!.some((finding) => finding.file === 'main.tf')).toBe(true);
        expect(artifacts.sast!.some((finding) => finding.file === 'config.py')).toBe(true);
        expect(artifacts.durationMs).toBeGreaterThan(0);
    }, 900_000);

    it('ne lance pas les étapes qu’on ne lui demande pas', async () => {
        const artifacts = await runner.run({ url: origin, branch: 'main', runDependencies: false, runIac: false, runSast: false });

        // `null` et non `[]` : une étape non demandée n'a rien observé, et l'ingestion ne
        // doit surtout pas la lire comme « analysé, propre ».
        expect(artifacts.dependencies).toBeNull();
        expect(artifacts.iac).toBeNull();
        expect(artifacts.sast).toBeNull();
        expect(artifacts.secrets).not.toBeNull();
    }, 900_000);

    it('échoue franchement quand le clone échoue', async () => {
        // Le clone est la seule étape bloquante : sans arbre, continuer produirait des
        // listes vides qui résoudraient tout le backlog de la cible.
        await expect(runner.run({ url: origin, branch: 'inexistante' })).rejects.toThrow(/inexistante/);
    }, 300_000);

    it('retient l’échec d’un scanner sans couler le scan', async () => {
        const brittle = new ScanRunner(
            containers,
            {
                generateSbom: async () => {
                    throw new Error('syft indisponible');
                },
                scanSbom: async () => null
            } as never
        );

        const artifacts = await brittle.run({ url: origin, branch: 'main', runIac: false, runSast: false });

        expect(artifacts.failures).toEqual([{ step: 'dépendances', reason: 'syft indisponible' }]);
        // L'artefact reste `null`, donc le backlog de dépendances est laissé tranquille…
        expect(artifacts.dependencies).toBeNull();
        // …et les autres étapes ont bien tourné.
        expect(artifacts.secrets).not.toBeNull();
    }, 900_000);
});
