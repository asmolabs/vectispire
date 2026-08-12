import { cp } from 'node:fs/promises';
import { join } from 'node:path';
import { cloneRepository } from './git-clone';
import { ContainerRunner } from './container-runner';
import { DependencyScanner, type DependencyFinding, type Sbom } from './scanners/dependencies';
import { GitleaksScanner, type SecretFinding } from './scanners/gitleaks';
import { IacScanner, type IacFinding } from './scanners/iac';
import { SastScanner, type SastFinding } from './scanners/sast';
import { withWorkspace, type Workspace } from './workspace';

/**
 * L'exécution d'un scan : cloner, lancer les scanners, rendre la sortie brute.
 *
 * **Ni base de données, ni entité, ni clé de chiffrement, ni réglage.** Il prend une tâche
 * et rend des artefacts. Ce n'est pas du rangement mais la contrainte qui rend les agents
 * possibles : un agent distant a une socket Docker et un répertoire temporaire, pas
 * l'accès au plan de contrôle. Le seul code qu'il puisse exécuter est du code de cette
 * forme — et c'est exactement celui-ci qui tournera là-bas, dans le même ordre.
 *
 * **Chaque étape est indépendante des autres.** L'échec d'un scanner ne coule pas le
 * scan : son artefact reste `null`, ce que l'ingestion lit comme « pas regardé » et non
 * comme « rien trouvé ». Seul le clone est bloquant — sans arbre, il n'y a rien à
 * analyser.
 */

/** Ce qu'un scan doit faire. Décidé par le plan de contrôle, exécuté par le coureur. */
export interface ScanTask {
    url: string;
    branch: string;
    subPath?: string;
    /** La clé privée déchiffrée, ou `null` pour un dépôt public. */
    privateKey?: string | null;
    /** Chaque étape est optionnelle : un opérateur peut n'en vouloir qu'une partie. */
    runDependencies?: boolean;
    runSecrets?: boolean;
    runIac?: boolean;
    runSast?: boolean;
}

/**
 * Ce qu'un scan a produit.
 *
 * **`null` partout signifie « l'étape n'a pas tourné », `[]` signifie « rien trouvé ».**
 * La distinction décide du sort du backlog de chaque type, et c'est pourquoi ces champs
 * sont optionnels plutôt que garnis de listes vides par défaut.
 */
export interface ScanArtifacts {
    sbom: Sbom | null;
    dependencies: DependencyFinding[] | null;
    secrets: SecretFinding[] | null;
    iac: IacFinding[] | null;
    sast: SastFinding[] | null;
    /** Ce qui a échoué, pour que l'opérateur sache ce qu'il ne voit pas. */
    failures: { step: string; reason: string }[];
    durationMs: number;
}

/** L'arbre de règles embarqué, copié dans l'espace de travail de chaque scan. */
const BUNDLED_RULES = join(__dirname, 'rules', 'semgrep');

export class ScanRunner {
    constructor(
        private readonly containers = new ContainerRunner(),
        private readonly dependencies = new DependencyScanner(containers),
        private readonly secrets = new GitleaksScanner(containers),
        private readonly iac = new IacScanner(containers),
        private readonly sast = new SastScanner(containers)
    ) {}

    async run(task: ScanTask): Promise<ScanArtifacts> {
        const started = Date.now();
        return withWorkspace(async (workspace) => {
            // Bloquant, et le seul à l'être : sans arbre il n'y a rien à analyser, et
            // continuer produirait des listes vides qui résoudraient tout le backlog.
            await cloneRepository({
                url: task.url,
                branch: task.branch,
                into: workspace.source,
                privateKey: task.privateKey ?? null
            });

            const artifacts: ScanArtifacts = {
                sbom: null,
                dependencies: null,
                secrets: null,
                iac: null,
                sast: null,
                failures: [],
                durationMs: 0
            };

            if (task.runDependencies !== false) {
                await this.step(artifacts, 'dépendances', async () => {
                    artifacts.sbom = await this.dependencies.generateSbom(workspace, task.subPath);
                    if (artifacts.sbom) artifacts.dependencies = await this.dependencies.scanSbom(workspace, artifacts.sbom);
                });
            }

            if (task.runSecrets !== false) {
                await this.step(artifacts, 'secrets', async () => {
                    artifacts.secrets = await this.secrets.scan(workspace, task.subPath);
                });
            }

            if (task.runIac !== false) {
                await this.step(artifacts, 'IaC', async () => {
                    artifacts.iac = await this.iac.scan(workspace, task.subPath);
                });
            }

            if (task.runSast) {
                await this.step(artifacts, 'SAST', async () => {
                    await this.placeRules(workspace);
                    artifacts.sast = await this.sast.scan(workspace, task.subPath);
                });
            }

            artifacts.durationMs = Date.now() - started;
            return artifacts;
        });
    }

    /**
     * Exécute une étape, et retient son échec sans l'interrompre.
     *
     * L'artefact reste `null` : c'est ce qui distingue « pas regardé » de « rien trouvé »,
     * et ce qui empêche l'échec d'un scanner de résoudre tout le backlog de son type.
     */
    private async step(artifacts: ScanArtifacts, name: string, body: () => Promise<void>): Promise<void> {
        try {
            await body();
        } catch (error) {
            artifacts.failures.push({ step: name, reason: (error as Error).message });
        }
    }

    /**
     * Copie l'arbre de règles dans l'espace de travail.
     *
     * Détour apparent — les règles existent déjà sur le disque, à côté de ce module — mais
     * c'est le seul emplacement qui fonctionne partout : les chemins de volume sont résolus
     * par le *démon* Docker, pas par le processus qui l'appelle. Quand Zanshin tourne
     * lui-même dans un conteneur avec la socket montée, un répertoire de son image est
     * invisible du conteneur frère.
     */
    private async placeRules(workspace: Workspace): Promise<void> {
        await cp(BUNDLED_RULES, workspace.rules, { recursive: true });
    }
}
