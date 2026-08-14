import { readFile, rm } from 'node:fs/promises';
import { join, posix } from 'node:path';
import { ContainerRunner, ScannerExecutionError } from '../container-runner';
import { RULES_SUBDIR, SOURCE_SUBDIR, type Workspace } from '../workspace';
import { GITLEAKS_IMAGE } from './images';

/**
 * La recherche de secrets codés en dur.
 *
 * **Le rapport est écrit à la racine de l'espace de travail, jamais dans l'arbre scanné.**
 * Il doit vivre dans le volume monté pour que le conteneur puisse l'écrire, et il contient
 * **chaque secret détecté en clair** — le laisser dans l'arbre le donnerait à lire à
 * l'étape suivante, y compris à un modèle de revue. La séparation `source/` est ce qui
 * rend cela structurel plutôt qu'une question de nom de fichier.
 *
 * Il est supprimé dès qu'il est lu, sans attendre la disparition de l'espace de travail :
 * un fichier de secrets en clair ne doit exister que le temps strictement nécessaire.
 */

const REPORT_FILENAME = 'zanshin-gitleaks-report.json';

/** Ce que gitleaks rend pour un secret trouvé. Seuls les champs utilisés sont déclarés. */
export interface GitleaksFinding {
    RuleID: string;
    Description: string;
    File: string;
    StartLine: number;
    /** L'empreinte que gitleaks calcule lui-même — utile, mais jamais le secret. */
    Fingerprint?: string;
    /** Le secret en clair. Présent dans le rapport, **jamais** conservé au-delà. */
    Secret?: string;
    Match?: string;
    Entropy?: number;
}

/** Ce que Zanshin garde d'un secret : où il est, quelle règle l'a trouvé. Pas sa valeur. */
export interface SecretFinding {
    rule: string;
    description: string;
    file: string;
    line: number;
    fingerprint: string | null;
}

export class GitleaksScanner {
    constructor(private readonly runner = new ContainerRunner()) {}

    /**
     * Rend les secrets trouvés, ou lève.
     *
     * Ne rend **jamais** `[]` pour dire « je n'ai pas tourné » : un tableau vide signifie
     * « analysé, aucun secret », ce qui résout tout le backlog de ce type. Un échec lève,
     * et l'appelant décide.
     */
    async scan(workspace: Workspace, subPath = ''): Promise<SecretFinding[]> {
        // Chemin POSIX : la cible est un chemin *dans le conteneur*, qui est un Linux,
        // quelle que soit la machine qui lance le scan.
        const source = subPath ? posix.join('/repo', SOURCE_SUBDIR, subPath) : posix.join('/repo', SOURCE_SUBDIR);
        const label = 'gitleaks (recherche de secrets)';

        const result = await this.runner.run({
            image: GITLEAKS_IMAGE,
            command: [
                'detect',
                `--source=${source}`,
                // **La configuration vient de Zanshin, jamais de la cible.**
                //
                // Sans `--config`, gitleaks retombe sur `<source>/.gitleaks.toml` — un
                // fichier du dépôt scanné, donc écrit par qui on audite — et l'utilise *à
                // la place* de son jeu de règles intégré. Un `.gitleaks.toml` vide avec une
                // liste d'exclusion universelle éteignait la détection : sortie 0, rapport
                // vide, `[]` rendu. Et `[]` veut dire « analysé, rien trouvé », donc la
                // résolution en silence de tout l'historique des secrets de cette cible,
                // triage compris. Le dépôt fermait ses propres constats.
                `--config=${posix.join('/repo', RULES_SUBDIR, 'gitleaks', 'gitleaks.toml')}`,
                // `--no-git` : l'arbre est cloné en profondeur 1, donc rejouer l'histoire
                // ne trouverait presque rien tout en coûtant le temps de la parcourir.
                '--no-git',
                '--report-format=json',
                `--report-path=/repo/${REPORT_FILENAME}`,
                // gitleaks sort en 1 quand il trouve des secrets. Ici c'est un résultat
                // attendu, pas un échec de conteneur : le code est neutralisé et les
                // résultats sont lus dans le fichier. Tout *autre* code non nul reste un
                // vrai échec et lève.
                '--exit-code=0'
            ],
            // En écriture : le conteneur doit pouvoir y déposer son rapport.
            binds: [{ source: workspace.root, target: '/repo' }],
            label,
            // Aucun réseau : gitleaks n'a rien à aller chercher.
            network: false,
            // L'espace de travail est un `mkdtemp` en 0700 appartenant à l'utilisateur de
            // Zanshin ; l'image tourne en utilisateur non privilégié et ne le lirait pas.
            asRoot: true
        });

        if (result.exitCode !== 0) {
            throw new ScannerExecutionError(label, result.exitCode, result.stderr);
        }

        const reportPath = join(workspace.root, REPORT_FILENAME);
        try {
            const content = (await readFile(reportPath, 'utf8')).trim();
            if (!content) return [];
            return (JSON.parse(content) as GitleaksFinding[]).map(toSecretFinding);
        } catch (error) {
            // Absence de rapport = aucun secret : gitleaks n'écrit rien quand il ne trouve
            // rien, selon la version. Distinguer ce cas d'un échec serait plus juste, mais
            // le code de retour l'a déjà fait juste au-dessus.
            if ((error as NodeJS.ErrnoException).code === 'ENOENT') return [];
            throw error;
        } finally {
            await rm(reportPath, { force: true });
        }
    }
}

/**
 * Ne garde que ce qui sert à corriger, **jamais le secret lui-même**.
 *
 * Le rapport contient la valeur en clair ; la recopier dans un constat la ferait entrer en
 * base, dans les exports SARIF, dans les tickets et dans les notifications. Un secret
 * détecté doit être révoqué, pas archivé — le fichier et la ligne suffisent à le trouver.
 */
function toSecretFinding(finding: GitleaksFinding): SecretFinding {
    return {
        rule: finding.RuleID,
        description: finding.Description,
        // Le chemin rendu par gitleaks est celui du conteneur ; l'appelant attend un
        // chemin relatif à l'arbre scanné.
        file: finding.File.replace(new RegExp(`^/repo/${SOURCE_SUBDIR}/?`), ''),
        line: finding.StartLine,
        fingerprint: finding.Fingerprint ?? null
    };
}
