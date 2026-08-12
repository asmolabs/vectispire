import { execFile, spawn, type ChildProcess } from 'node:child_process';
import { mkdtemp, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { CloneError, cloneRepository } from './git-clone';
import { SOURCE_SUBDIR, withWorkspace } from './workspace';

const run = promisify(execFile);

/**
 * Le clone, contre de vrais dépôts git locaux.
 *
 * **Locaux et non distants** : un test qui clone depuis GitHub échoue quand le réseau
 * tousse, et un test qui échoue pour une raison étrangère à son sujet finit par être
 * ignoré. Un dépôt `file://` exerce le même chemin de code — `git clone` avec ses
 * options, la profondeur, la branche — sans dépendre de personne.
 *
 * Le dépôt est servi par `git daemon` sur `git://127.0.0.1`, un schéma que la validation
 * autorise. Un chemin nu ou `file://` serait plus simple et serait refusé — correctement,
 * puisque `file://` ferait cloner le disque de la machine qui scanne. Le test emprunte
 * donc le même chemin que la production, jusqu'au protocole.
 */
describe('clone d’un dépôt', () => {
    /** L'URL servie par le démon, la seule que la validation accepte. */
    let origin: string;
    let scratch: string;
    let daemon: ChildProcess;

    beforeAll(async () => {
        scratch = await mkdtemp(join(tmpdir(), 'zanshin-origin-'));
        const bare = join(scratch, 'origine.git');

        await run('git', ['init', '--bare', '--initial-branch=main', bare]);

        // Un dépôt de travail pour y pousser un commit : un dépôt nu vide n'a pas de
        // branche, et cloner une branche inexistante est un autre cas de test.
        const working = join(scratch, 'travail');
        await run('git', ['clone', bare, working]);
        await writeFile(join(working, 'README.md'), '# Dépôt d’essai\n');
        await run('git', ['-C', working, 'add', '.']);
        await run('git', ['-C', working, '-c', 'user.email=test@zanshin', '-c', 'user.name=Test', 'commit', '-m', 'premier']);
        await run('git', ['-C', working, 'push', 'origin', 'main']);

        // Port fixe mais peu fréquenté ; le démon meurt avec la campagne.
        const port = 9418 + (process.pid % 500);
        daemon = spawn('git', ['daemon', `--base-path=${scratch}`, '--export-all', '--reuseaddr', `--port=${port}`, scratch], { stdio: 'ignore' });
        origin = `git://127.0.0.1:${port}/origine.git`;
        await new Promise((resolve) => setTimeout(resolve, 400));
    }, 60_000);

    afterAll(async () => {
        daemon?.kill();
        await rm(scratch, { recursive: true, force: true });
    });

    it('clone la branche demandée dans le sous-répertoire source', async () => {
        await withWorkspace(async (workspace) => {
            await cloneRepository({ url: origin, branch: 'main', into: workspace.source });

            const entries = await readdir(workspace.source);
            expect(entries).toContain('README.md');
            expect(await readFile(join(workspace.source, 'README.md'), 'utf8')).toContain('Dépôt d’essai');
        });
    }, 30_000);

    it('ne clone que la révision courante', async () => {
        await withWorkspace(async (workspace) => {
            await cloneRepository({ url: origin, branch: 'main', into: workspace.source });

            // `--depth 1` : un scan regarde l'arbre courant, pas l'histoire. Sur un dépôt
            // de dix ans, la différence est celle entre quelques mégaoctets et plusieurs
            // gigaoctets, à chaque scan.
            const { stdout } = await run('git', ['-C', workspace.source, 'rev-list', '--count', 'HEAD']);
            expect(Number(stdout.trim())).toBe(1);
        });
    }, 30_000);

    it('supprime l’espace de travail même quand le corps échoue', async () => {
        let captured = '';
        await expect(
            withWorkspace(async (workspace) => {
                captured = workspace.root;
                await cloneRepository({ url: origin, branch: 'main', into: workspace.source });
                throw new Error('échec simulé pendant le scan');
            })
        ).rejects.toThrow('échec simulé');

        // Les échecs sont le cas où l'on oublie de nettoyer, et le seul où cela compte :
        // l'arbre cloné peut peser, et le rapport gitleaks contient des secrets en clair.
        await expect(readdir(captured)).rejects.toThrow();
    }, 30_000);

    it('dit quelle branche manque plutôt que de rendre l’erreur brute de git', async () => {
        await withWorkspace(async (workspace) => {
            const failure = await cloneRepository({ url: origin, branch: 'inexistante', into: workspace.source }).catch((error) => error);

            expect(failure).toBeInstanceOf(CloneError);
            expect(failure.message).toContain('inexistante');
            expect(failure.message).toContain("n'existe pas");
        });
    }, 30_000);

    it('refuse une URL que git exécuterait, avant même de lancer git', async () => {
        await withWorkspace(async (workspace) => {
            // `ext::` fait exécuter une commande arbitraire par git lui-même. La
            // validation à la saisie ne suffit pas : des lignes antérieures existent.
            await expect(cloneRepository({ url: 'ext::sh -c whoami', branch: 'main', into: workspace.source })).rejects.toThrow(/refusée/);
        });
    }, 30_000);

    it('ne laisse pas la clé privée derrière lui', async () => {
        const before = await readdir(tmpdir());
        await withWorkspace(async (workspace) => {
            // Le clone échouera — la clé ne vaut rien pour un dépôt local — et c'est le
            // point : le fichier de clé doit disparaître aussi sur le chemin d'erreur.
            await cloneRepository({
                url: origin,
                branch: 'main',
                into: workspace.source,
                privateKey: '-----BEGIN OPENSSH PRIVATE KEY-----\nfaux\n-----END OPENSSH PRIVATE KEY-----'
            }).catch(() => undefined);
        });

        const after = await readdir(tmpdir());
        const leaked = after.filter((entry) => entry.startsWith('zanshin-key-') && !before.includes(entry));
        expect(leaked).toEqual([]);
    }, 30_000);

    it('crée le source à côté de la racine, pas à sa place', async () => {
        await withWorkspace(async (workspace) => {
            await cloneRepository({ url: origin, branch: 'main', into: workspace.source });
            await writeFile(join(workspace.root, 'sbom.json'), '{}');

            // Un artefact écrit à la racine n'est pas visible de l'arbre scanné. C'est ce
            // qui empêche le rapport gitleaks — qui contient les secrets en clair — d'être
            // relu par une étape suivante.
            expect(await readdir(workspace.source)).not.toContain('sbom.json');
            expect(await readdir(workspace.root)).toEqual(expect.arrayContaining(['sbom.json', SOURCE_SUBDIR]));
        });
    }, 30_000);
});
