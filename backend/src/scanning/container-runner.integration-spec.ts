import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import {
    ContainerRunner,
    ScannerExecutionError,
    SCANNER_LABEL,
    ScannerTimeoutError,
    parseScannerJson
} from './container-runner';
import { withWorkspace } from './workspace';

/**
 * Le lanceur de conteneurs, contre un vrai démon Docker.
 *
 * L'image est `alpine`, pas un scanner : ce qui est vérifié ici est le **lanceur** — le
 * réseau coupé, les flux séparés, l'expiration, le nettoyage — et le faire avec une image
 * de trois mégaoctets rend la suite exécutable partout. Les scanners réels seront exercés
 * par leurs propres tests, sur leur propre sortie.
 */
const IMAGE = 'alpine:3.20';

describe('exécution d’un conteneur de scanner', () => {
    const runner = new ContainerRunner();

    beforeAll(async () => {
        if (!(await runner.isAvailable())) {
            throw new Error(
                'Le démon Docker est injoignable. Ces tests exercent le lancement de conteneurs et ne peuvent pas être simulés : ' +
                    'les sauter rapporterait vert sans rien vérifier.'
            );
        }
        // Tirée une fois : sinon chaque test paierait le téléchargement et le premier
        // expirerait sur une machine froide.
        await new Promise<void>((resolve, reject) => {
            void runner['docker'].pull(IMAGE, (error: Error | null, stream: NodeJS.ReadableStream) => {
                if (error) return reject(error);
                runner['docker'].modem.followProgress(stream, (done: Error | null) => (done ? reject(done) : resolve()));
            });
        });
    }, 180_000);

    it('rend la sortie standard et le code de retour', async () => {
        const result = await runner.run({ image: IMAGE, command: ['echo', 'bonjour'], binds: [], label: 'echo' });

        expect(result.stdout.trim()).toBe('bonjour');
        expect(result.exitCode).toBe(0);
    }, 60_000);

    it('garde les deux flux séparés', async () => {
        // Le point : une sortie combinée corromprait le JSON de stdout, et taire stderr
        // perdrait l'explication du scanner — celle qui finit sous les yeux de l'opérateur.
        const result = await runner.run({
            image: IMAGE,
            command: ['sh', '-c', `echo '{"ok":true}'; echo avertissement >&2`],
            binds: [],
            label: 'flux'
        });

        expect(JSON.parse(result.stdout.trim())).toEqual({ ok: true });
        expect(result.stderr).toContain('avertissement');
    }, 60_000);

    it('coupe le réseau par défaut', async () => {
        // La propriété qui compte : un scanner qui analyse du code hostile ne doit pas
        // pouvoir en faire sortir quoi que ce soit.
        const result = await runner.run({
            image: IMAGE,
            command: ['sh', '-c', 'ip route | wc -l'],
            binds: [],
            label: 'réseau'
        });

        expect(result.stdout.trim()).toBe('0');
    }, 60_000);

    it('monte l’espace de travail et le laisse lisible', async () => {
        await withWorkspace(async (workspace) => {
            await writeFile(join(workspace.root, 'cible.txt'), 'contenu\n');

            const result = await runner.run({
                image: IMAGE,
                command: ['cat', '/repo/cible.txt'],
                binds: [{ source: workspace.root, target: '/repo', readOnly: true }],
                label: 'montage',
                asRoot: true
            });

            expect(result.stdout).toContain('contenu');
        });
    }, 60_000);

    it('empêche l’écriture sur un montage en lecture seule', async () => {
        await withWorkspace(async (workspace) => {
            const result = await runner.run({
                image: IMAGE,
                command: ['sh', '-c', 'touch /repo/ecrit 2>&1; echo code=$?'],
                binds: [{ source: workspace.root, target: '/repo', readOnly: true }],
                label: 'lecture-seule',
                asRoot: true
            });

            // Root dans le conteneur ne suffit pas : c'est le montage qui refuse.
            expect(result.stdout).toContain('code=1');
        });
    }, 60_000);

    it('arrête un conteneur qui dépasse son temps, plutôt que de l’abandonner', async () => {
        const failure = await runner
            .run({ image: IMAGE, command: ['sleep', '60'], binds: [], label: 'lent', timeoutMs: 2000 })
            .catch((error) => error);

        expect(failure).toBeInstanceOf(ScannerTimeoutError);
        // Abandonner l'attente laisserait le conteneur tourner pendant que Zanshin
        // considère le scan terminé — il consommerait sa mémoire et ses processus.
        expect(failure.message).toMatch(/dépassé/);
    }, 60_000);

    it('ne laisse pas de conteneur derrière lui', async () => {
        const docker = runner['docker'];
        // **Filtré sur l'étiquette de Zanshin, et non compté sur tout l'hôte.** Les suites
        // d'intégration tournent en parallèle et démarrent chacune leurs conteneurs de base
        // de test : un décompte global mesurait leur va-et-vient, pas la propreté de ce
        // coureur — il rendait « après < avant », ce qui n'a aucun sens pour une fuite.
        const filters = { label: [SCANNER_LABEL] };
        const before = (await docker.listContainers({ all: true, filters })).length;

        await runner.run({ image: IMAGE, command: ['true'], binds: [], label: 'propre' });
        await runner.run({ image: IMAGE, command: ['sleep', '60'], binds: [], label: 'lent', timeoutMs: 1500 }).catch(() => undefined);

        const after = (await docker.listContainers({ all: true, filters })).length;
        // Y compris sur le chemin d'expiration : un conteneur oublié retient son espace de
        // travail, donc le clone entier.
        expect(after).toBe(before);
    }, 90_000);

    describe('lecture de la sortie', () => {
        it('rend l’objet analysé', () => {
            const parsed = parseScannerJson<{ ok: boolean }>({ stdout: '{"ok":true}', stderr: '', exitCode: 0 }, 'test');
            expect(parsed).toEqual({ ok: true });
        });

        it('rend null sur une sortie vide, pas un tableau vide', () => {
            // La distinction décide du sort de tout le backlog : une liste vide fait
            // résoudre chaque problème du type, un `null` ne fait rien.
            expect(parseScannerJson({ stdout: '  ', stderr: '', exitCode: 0 }, 'test')).toBeNull();
        });

        it('rend null sur un JSON tronqué plutôt que de lever', () => {
            expect(parseScannerJson({ stdout: '{"partiel":', stderr: '', exitCode: 0 }, 'test')).toBeNull();
        });

        it('lève sur un code de retour non prévu, en gardant l’explication du scanner', () => {
            const failure = (() => {
                try {
                    parseScannerJson({ stdout: '', stderr: 'image introuvable', exitCode: 2 }, 'grype');
                    return null;
                } catch (error) {
                    return error;
                }
            })();

            expect(failure).toBeInstanceOf(ScannerExecutionError);
            expect((failure as Error).message).toContain('image introuvable');
        });

        it('accepte les codes qu’un scanner utilise pour « j’ai trouvé quelque chose »', () => {
            // gitleaks sort en 1 quand il trouve des secrets. Traiter cela comme un échec
            // ferait perdre exactement les scans qui ont trouvé quelque chose.
            expect(parseScannerJson({ stdout: '[]', stderr: '', exitCode: 1 }, 'gitleaks', [0, 1])).toEqual([]);
        });
    });
});
