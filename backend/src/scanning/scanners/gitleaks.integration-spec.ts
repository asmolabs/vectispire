import { mkdir, readdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { ContainerRunner } from '../container-runner';
import { placeBundledRules } from '../bundled-rules';
import { withWorkspace, type Workspace } from '../workspace';
import { GitleaksScanner } from './gitleaks';
import { GITLEAKS_IMAGE } from './images';

/**
 * gitleaks de bout en bout : une vraie image, un vrai secret semé, de vrais constats.
 *
 * **Le secret semé doit être détectable pour de vrai.** La première version employait
 * `AKIAIOSFODNN7EXAMPLE`, la clé d'exemple de la documentation AWS — que gitleaks connaît
 * et exclut délibérément. Le test passait sans rien prouver, ce qui est exactement le
 * défaut que ces tests existent pour empêcher. Les valeurs ci-dessous sont inventées,
 * n'ouvrent rien, et sont vérifiées comme reconnues par l'outil.
 */
const AWS_KEY = 'AKIA' + 'Z6TJ4KQXPL2WMNBV';
const STRIPE_KEY = 'sk_live_' + '51H8xKzQwErTyUiOpAsDfGhJ';

describe('recherche de secrets', () => {
    const runner = new ContainerRunner();
    const scanner = new GitleaksScanner(runner);

    /**
     * Un espace de travail préparé **comme le runner le prépare** : arbre vide et règles en
     * place. Les poser à la main dans chaque test aurait laissé ces tests diverger du
     * chemin réel le jour où le placement change.
     */
    async function withPreparedWorkspace(body: (workspace: Workspace) => Promise<void>): Promise<void> {
        await withWorkspace(async (workspace) => {
            await mkdir(workspace.source, { recursive: true });
            await placeBundledRules(workspace);
            await body(workspace);
        });
    }

    beforeAll(async () => {
        if (!(await runner.isAvailable())) {
            throw new Error('Le démon Docker est injoignable : ce test exerce un vrai conteneur et ne peut pas être simulé.');
        }
        await new Promise<void>((resolve, reject) => {
            void runner['docker'].pull(GITLEAKS_IMAGE, (error: Error | null, stream: NodeJS.ReadableStream) => {
                if (error) return reject(error);
                runner['docker'].modem.followProgress(stream, (done: Error | null) => (done ? reject(done) : resolve()));
            });
        });
    }, 300_000);

    it('trouve un secret codé en dur et dit où il est', async () => {
        await withPreparedWorkspace(async (workspace) => {
            await writeFile(
                join(workspace.source, 'config.py'),
                ['import boto3', '', `AWS_ACCESS_KEY_ID = "${AWS_KEY}"`, `STRIPE_KEY = "${STRIPE_KEY}"`, ''].join('\n')
            );

            const findings = await scanner.scan(workspace);

            expect(findings.length).toBeGreaterThan(0);
            const found = findings.find((finding) => finding.file === 'config.py');
            expect(found).toBeDefined();
            expect(found!.line).toBeGreaterThan(0);
            expect(found!.rule).toBeTruthy();
        }, 300_000);
    }, 300_000);

    it('ne conserve jamais la valeur du secret', async () => {
        await withPreparedWorkspace(async (workspace) => {
            await writeFile(join(workspace.source, 'config.py'), `AWS_ACCESS_KEY_ID = "${AWS_KEY}"\nSTRIPE_KEY = "${STRIPE_KEY}"\n`);

            const findings = await scanner.scan(workspace);

            // Un secret détecté doit être révoqué, pas archivé. Le recopier dans un constat
            // le ferait entrer en base, dans les exports SARIF, dans les tickets et dans
            // les notifications — c'est-à-dire le diffuser davantage qu'il ne l'était.
            const serialized = JSON.stringify(findings);
            expect(serialized).not.toContain(STRIPE_KEY);
            expect(serialized).not.toContain(AWS_KEY);
        });
    }, 300_000);

    it('supprime le rapport dès qu’il l’a lu', async () => {
        await withPreparedWorkspace(async (workspace) => {
            await writeFile(join(workspace.source, 'config.py'), `AWS_ACCESS_KEY_ID = "${AWS_KEY}"\n`);

            await scanner.scan(workspace);

            // Le rapport contient chaque secret en clair : il ne doit exister que le temps
            // strictement nécessaire, sans attendre la disparition de l'espace de travail.
            const entries = await readdir(workspace.root);
            expect(entries.filter((entry) => entry.includes('gitleaks'))).toEqual([]);
        });
    }, 300_000);

    it('écrit son rapport hors de l’arbre scanné', async () => {
        await withPreparedWorkspace(async (workspace) => {
            await writeFile(join(workspace.source, 'config.py'), `AWS_ACCESS_KEY_ID = "${AWS_KEY}"\n`);

            await scanner.scan(workspace);

            // Si le rapport atterrissait dans `source/`, l'étape suivante le lirait comme
            // du code à analyser — y compris un modèle de revue, à qui l'on donnerait
            // ainsi tous les secrets du dépôt.
            expect(await readdir(workspace.source)).toEqual(['config.py']);
        });
    }, 300_000);

    it('rend une liste vide sur un arbre sans secret', async () => {
        await withPreparedWorkspace(async (workspace) => {
            await writeFile(join(workspace.source, 'propre.py'), 'def bonjour():\n    return "rien à cacher"\n');

            // Vide et non `null` : ici gitleaks a bel et bien tourné et n'a rien trouvé,
            // ce qui doit résoudre les secrets précédemment détectés.
            expect(await scanner.scan(workspace)).toEqual([]);
        });
    }, 300_000);

    it("ignore le .gitleaks.toml du dépôt scanné", async () => {
        await withPreparedWorkspace(async (workspace) => {
            await writeFile(join(workspace.source, 'config.py'), `AWS_ACCESS_KEY_ID = "${AWS_KEY}"\n`);
            // **La cible fournissait les règles de son propre audit.** Sans `--config`,
            // gitleaks retombe sur ce fichier et l'utilise *à la place* de son jeu intégré.
            // Celui-ci n'a aucune règle et exclut tout : l'outil sortait en 0 avec un
            // rapport vide, donc `[]` — « analysé, rien trouvé ». Le type `secret` entrait
            // alors dans `scannedTypes` et **tous les secrets ouverts de cette cible étaient
            // marqués résolus, triage compris**.
            await writeFile(
                join(workspace.source, '.gitleaks.toml'),
                ['title = "rien à voir"', '', '[allowlist]', 'description = "tout"', 'regexes = [".*"]', 'paths = [".*"]', ''].join('\n')
            );

            const findings = await scanner.scan(workspace);

            expect(findings.some((finding) => finding.file === 'config.py')).toBe(true);
        });
    }, 300_000);

    it('ne regarde que le sous-chemin demandé', async () => {
        await withPreparedWorkspace(async (workspace) => {
            await mkdir(join(workspace.source, 'service'), { recursive: true });
            await writeFile(join(workspace.source, 'ailleurs.py'), `AWS_ACCESS_KEY_ID = "${AWS_KEY}"\n`);
            await writeFile(join(workspace.source, 'service', 'propre.py'), 'x = 1\n');

            // Un dépôt monorepo dont une seule application est surveillée : les secrets des
            // autres ne sont pas le sujet de ce scan.
            expect(await scanner.scan(workspace, 'service')).toEqual([]);
        });
    }, 300_000);
});
