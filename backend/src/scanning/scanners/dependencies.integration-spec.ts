import { mkdir, readdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { ContainerRunner } from '../container-runner';
import { withWorkspace } from '../workspace';
import { DependencyScanner } from './dependencies';
import { GRYPE_IMAGE, SYFT_IMAGE } from './images';

/**
 * Syft et Grype de bout en bout : un vrai inventaire, de vraies vulnérabilités.
 *
 * **La dépendance semée est réellement vulnérable.** `lodash@4.17.11` porte des CVE
 * publiées et corrigées de longue date : c'est une valeur sûre pour vérifier que la chaîne
 * entière fonctionne, sans dépendre d'une vulnérabilité découverte cette semaine — celle-ci
 * changerait de sévérité, ou disparaîtrait de la base, et le test deviendrait instable.
 *
 * Grype a besoin du réseau pour sa base : ces tests ne tournent donc pas hors ligne, et
 * c'est assumé. Le dire vaut mieux que de simuler une base et de ne rien vérifier.
 */
const PACKAGE_JSON = {
    name: 'cible-d-essai',
    version: '1.0.0',
    dependencies: { lodash: '4.17.11' }
};

/** `package-lock.json` minimal : Syft lit le verrou, pas la déclaration. */
const PACKAGE_LOCK = {
    name: 'cible-d-essai',
    version: '1.0.0',
    lockfileVersion: 2,
    requires: true,
    packages: {
        '': { name: 'cible-d-essai', version: '1.0.0', dependencies: { lodash: '4.17.11' } },
        'node_modules/lodash': {
            version: '4.17.11',
            resolved: 'https://registry.npmjs.org/lodash/-/lodash-4.17.11.tgz',
            integrity: 'sha512-cQKh8igo5QUhZ7lg38DYWAxMvjSAKG0A8wGSVimP07SIUEK2UO+arSRKbRZWtelMtN5V0Hkwh5ryOto/SshYIg=='
        }
    }
};

describe('analyse des dépendances', () => {
    const runner = new ContainerRunner();
    const scanner = new DependencyScanner(runner);

    beforeAll(async () => {
        if (!(await runner.isAvailable())) {
            throw new Error('Le démon Docker est injoignable : ces tests exercent de vrais conteneurs et ne peuvent pas être simulés.');
        }
        for (const image of [SYFT_IMAGE, GRYPE_IMAGE]) {
            await new Promise<void>((resolve, reject) => {
                void runner['docker'].pull(image, (error: Error | null, stream: NodeJS.ReadableStream) => {
                    if (error) return reject(error);
                    runner['docker'].modem.followProgress(stream, (done: Error | null) => (done ? reject(done) : resolve()));
                });
            });
        }
    }, 600_000);

    async function seed(workspace: { source: string }): Promise<void> {
        await mkdir(workspace.source, { recursive: true });
        await writeFile(join(workspace.source, 'package.json'), JSON.stringify(PACKAGE_JSON, null, 2));
        await writeFile(join(workspace.source, 'package-lock.json'), JSON.stringify(PACKAGE_LOCK, null, 2));
    }

    it('dresse l’inventaire des dépendances', async () => {
        await withWorkspace(async (workspace) => {
            await seed(workspace);

            const sbom = await scanner.generateSbom(workspace);

            expect(sbom).not.toBeNull();
            const artifacts = (sbom as { artifacts?: { name?: string; version?: string }[] }).artifacts ?? [];
            expect(artifacts.some((artifact) => artifact.name === 'lodash' && artifact.version === '4.17.11')).toBe(true);
        });
    }, 300_000);

    it('n’écrit rien dans l’arbre analysé', async () => {
        await withWorkspace(async (workspace) => {
            await seed(workspace);
            await scanner.generateSbom(workspace);

            // Monté en lecture seule : Syft n'a aucune raison d'écrire dans l'arbre, et le
            // lui interdire élimine la question de savoir s'il le fait.
            expect((await readdir(workspace.source)).sort()).toEqual(['package-lock.json', 'package.json']);
        });
    }, 300_000);

    it('trouve les vulnérabilités connues du SBOM', async () => {
        await withWorkspace(async (workspace) => {
            await seed(workspace);
            const sbom = await scanner.generateSbom(workspace);

            const findings = await scanner.scanSbom(workspace, sbom!);

            expect(findings).not.toBeNull();
            expect(findings!.length).toBeGreaterThan(0);
            const lodash = findings!.find((finding) => finding.packageName === 'lodash');
            expect(lodash).toBeDefined();
            expect(lodash!.identifier).toMatch(/^(CVE|GHSA)/);
            expect(lodash!.installedVersion).toBe('4.17.11');
        });
    }, 600_000);

    it('rend les sévérités dans le vocabulaire de Zanshin', async () => {
        await withWorkspace(async (workspace) => {
            await seed(workspace);
            const sbom = await scanner.generateSbom(workspace);
            const findings = await scanner.scanSbom(workspace, sbom!);

            // Grype écrit « High » ; le vocabulaire de Zanshin est en minuscules. Une
            // sévérité hors vocabulaire crée un constat qui n'entre dans aucun seuil de
            // politique — visible dans le backlog, incapable de faire échouer un gate.
            for (const finding of findings!) {
                expect(finding.severity).toBe(finding.severity.toLowerCase());
                expect(['critical', 'high', 'medium', 'low', 'negligible', 'unknown']).toContain(finding.severity);
            }
        });
    }, 600_000);

    it('rend les versions correctrices sous forme de chaîne', async () => {
        await withWorkspace(async (workspace) => {
            await seed(workspace);
            const sbom = await scanner.generateSbom(workspace);
            const findings = await scanner.scanSbom(workspace, sbom!);

            // `fixVersions` sert de drapeau « corrigeable » dans le gate, où une chaîne
            // vide vaut « aucun correctif ». lodash 4.17.11 a des correctifs publiés.
            const fixable = findings!.filter((finding) => finding.fixVersions !== '');
            expect(fixable.length).toBeGreaterThan(0);
            expect(typeof fixable[0].fixVersions).toBe('string');
        });
    }, 600_000);

    it('laisse le SBOM disponible pour l’export', async () => {
        await withWorkspace(async (workspace) => {
            await seed(workspace);
            const sbom = await scanner.generateSbom(workspace);
            await scanner.scanSbom(workspace, sbom!);

            // Le SBOM a une valeur propre : il répond à « qu'y a-t-il dans cette
            // application » et permet de rejouer l'analyse sans re-parcourir le code.
            expect(await readdir(workspace.root)).toContain('sbom.json');
        });
    }, 600_000);

    it('rend un inventaire vide plutôt que null sur un arbre sans dépendance', async () => {
        await withWorkspace(async (workspace) => {
            await mkdir(workspace.source, { recursive: true });
            await writeFile(join(workspace.source, 'README.md'), '# rien\n');

            const sbom = await scanner.generateSbom(workspace);

            // Syft a tourné : il rend un SBOM sans artefact, ce qui n'est pas la même chose
            // que de ne pas avoir tourné.
            expect(sbom).not.toBeNull();
            expect((sbom as { artifacts?: unknown[] }).artifacts ?? []).toEqual([]);
        });
    }, 300_000);
});
