import { execFile } from 'node:child_process';
import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { ContainerRunner } from '../container-runner';
import { placeBundledRules } from '../bundled-rules';
import { withWorkspace, type Workspace } from '../workspace';
import { SEMGREP_IMAGE } from './images';
import { SastScanner } from './sast';

/** Un appel que les règles embarquées reconnaissent à coup sûr. */
const DANGEREUX = 'def traite(entree):\n    return eval(entree)\n';

const run = promisify(execFile);

/**
 * Fait de ce répertoire un vrai dépôt git.
 *
 * Une cible réelle en est toujours un — elle sort de `git clone` — et c'est cette
 * différence qui décide de ce que semgrep accepte d'examiner.
 */
async function asGitRepository(directory: string): Promise<void> {
    await run('git', ['init', '--quiet'], { cwd: directory });
}

describe('analyse du code source', () => {
    const runner = new ContainerRunner();
    const scanner = new SastScanner(runner);

    beforeAll(async () => {
        if (!(await runner.isAvailable())) {
            throw new Error('Le démon Docker est injoignable : ce test exerce un vrai conteneur et ne peut pas être simulé.');
        }
        await new Promise<void>((resolve, reject) => {
            void runner['docker'].pull(SEMGREP_IMAGE, (error: Error | null, stream: NodeJS.ReadableStream) => {
                if (error) return reject(error);
                runner['docker'].modem.followProgress(stream, (done: Error | null) => (done ? reject(done) : resolve()));
            });
        });
    }, 900_000);

    async function seed(workspace: Workspace, code: string): Promise<void> {
        await mkdir(workspace.source, { recursive: true });
        await writeFile(join(workspace.source, 'app.py'), code);
        // Par la fonction de production, pas par une copie refaite ici : c'est elle qui
        // décide de la disposition que la ligne de commande de semgrep suppose.
        await placeBundledRules(workspace);
    }

    it('trouve un appel dangereux et rend le message de la règle', async () => {
        await withWorkspace(async (workspace) => {
            await seed(workspace, 'def traite(entree):\n    return eval(entree)\n');

            const findings = await scanner.scan(workspace);

            expect(findings).not.toBeNull();
            expect(findings!.length).toBe(1);
            const finding = findings![0];
            expect(finding.ruleId).toContain('eval-sur-entree');
            expect(finding.file).toBe('app.py');
            expect(finding.line).toBe(2);
            // Pour un constat SAST, le message *est* le constat : sans lui, le panneau de
            // détail affiche un identifiant de règle, un fichier et une ligne, et rien
            // d'exploitable.
            expect(finding.message).toContain('eval');
        });
    }, 900_000);

    it('traduit la sévérité dans le vocabulaire de Zanshin', async () => {
        await withWorkspace(async (workspace) => {
            await seed(workspace, 'x = eval(entree)\n');

            const findings = await scanner.scan(workspace);

            // `"ERROR".toLowerCase()` donnerait `error`, qui n'appartient à aucun seuil de
            // politique — le constat serait créé et n'entrerait dans aucun gate.
            expect(findings![0].severity).toBe('high');
        });
    }, 900_000);

    it('rend la catégorie, qui décide de la destination du constat', async () => {
        await withWorkspace(async (workspace) => {
            await seed(workspace, 'x = eval(entree)\n');

            // `security` va au backlog de sécurité, le reste à la qualité — qui ne fait
            // jamais échouer une compilation.
            expect((await scanner.scan(workspace))![0].category).toBe('security');
        });
    }, 900_000);

    it('rend une liste vide sur du code sans constat', async () => {
        await withWorkspace(async (workspace) => {
            await seed(workspace, 'import ast\n\ndef traite(entree):\n    return ast.literal_eval(entree)\n');

            // Vide et non `null` : semgrep a tourné et n'a rien trouvé.
            expect(await scanner.scan(workspace)).toEqual([]);
        });
    }, 900_000);

    it("analyse le code qu'un .gitignore de la cible exclut", async () => {
        await withWorkspace(async (workspace) => {
            await seed(workspace, DANGEREUX);
            // **Le dépôt décidait de ce qui serait analysé.** Sur un arbre git — ce qu'est
            // toujours une cible réelle — semgrep n'examine par défaut que les fichiers
            // suivis. Un `.gitignore` large, ou du code simplement non commité, sortait donc
            // du périmètre sans le dire : l'étape rendait `[]`, « analysé, rien trouvé »,
            // et résolvait le backlog SAST de la cible.
            await writeFile(join(workspace.source, '.gitignore'), '*\n');
            await asGitRepository(workspace.source);

            const findings = await scanner.scan(workspace);

            expect(findings).not.toBeNull();
            expect(findings!.length).toBeGreaterThan(0);
        });
    }, 900_000);

    it("rend null quand aucun fichier n'a été examiné", async () => {
        await withWorkspace(async (workspace) => {
            await seed(workspace, DANGEREUX);
            // Zéro fichier examiné n'est pas un arbre propre, c'est une analyse qui n'a pas
            // eu lieu. Sans ce garde-fou, un `.semgrepignore` déposé par la cible suffisait
            // à rendre `[]` — donc à faire disparaître tout son historique SAST.
            await writeFile(join(workspace.source, '.semgrepignore'), '*\n');

            expect(await scanner.scan(workspace)).toBeNull();
        });
    }, 900_000);

    it('rend null plutôt qu’une liste vide quand il ne peut pas tourner', async () => {
        // Sans quoi un plantage de semgrep résoudrait tout le backlog SAST de la cible.
        const brokenRunner = { run: async () => { throw new Error('démon indisponible'); } } as unknown as ContainerRunner;
        await withWorkspace(async (workspace) => {
            expect(await new SastScanner(brokenRunner).scan(workspace)).toBeNull();
        });
    }, 30_000);
});
