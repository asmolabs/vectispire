import { posix } from 'node:path';
import { ContainerRunner, parseScannerJson } from '../container-runner';
import { RULES_SUBDIR, SOURCE_SUBDIR, type Workspace } from '../workspace';
import { SEMGREP_IMAGE } from './images';

/**
 * L'analyse du code source lui-même.
 *
 * Plusieurs détails ci-dessous ont été établis contre la vraie image plutôt que supposés,
 * et chacun porte quelque chose :
 *
 * - **`semgrep` ouvre la commande.** L'image n'a pas de point d'entrée — son `Cmd` est
 *   `["semgrep", "--help"]` — contrairement à `bridgecrew/checkov`. Copier la forme
 *   d'appel de checkov produit une ligne de commande absurde et un code 2.
 * - **`--no-rewrite-rule-ids`.** Avec un `--config` pointant un *répertoire*, Semgrep
 *   préfixe chaque `check_id` du chemin relatif du fichier de règles. Réorganiser l'arbre
 *   de règles renommerait donc chaque identifiant — et l'identifiant entre dans
 *   l'empreinte d'un problème, si bien que **tout le backlog SAST se résoudrait pour
 *   réapparaître à neuf, triage perdu**.
 * - **Pas de `--error`.** `semgrep scan` sort en 0 quand il trouve quelque chose ; c'est
 *   `semgrep ci` qui sort en 1. Il n'y a donc pas d'équivalent de `--soft-fail` à passer,
 *   et tout code non nul est un vrai échec.
 * - **Réseau coupé**, comme gitleaks et checkov : les règles sont sur disque, et
 *   `--metrics=off` / `--disable-version-check` évitent que Semgrep ne passe son démarrage
 *   dans une expiration DNS vers semgrep.dev.
 * - **`--max-memory` sous le plafond du conteneur**, pour qu'un gros dépôt se dégrade par
 *   le limiteur de Semgrep plutôt que d'être tué en 137 par le tueur de mémoire.
 */

/**
 * Part des fichiers en erreur au-delà de laquelle le résultat vaut « n'a pas tourné ».
 *
 * Semgrep sort en 0 quand des fichiers expirent individuellement : une exécution où la
 * majorité du dépôt a été sautée est donc **indiscernable d'une exécution propre** par son
 * seul code de retour — et la lire comme propre résoudrait tout le backlog SAST de la
 * cible.
 */
const MAX_ERROR_RATIO = 0.25;

export interface SastFinding {
    /** L'identifiant de la règle. Entre dans l'empreinte : il ne doit pas bouger. */
    ruleId: string;
    /** `security` ou une catégorie de qualité — c'est ce qui décide de la destination. */
    category: string;
    severity: string;
    confidence: string | null;
    file: string;
    line: number;
    /** Le message de la règle. Pour un constat SAST, le message *est* le constat. */
    message: string;
}

interface SemgrepResult {
    check_id?: string;
    path?: string;
    start?: { line?: number };
    extra?: {
        message?: string;
        severity?: string;
        metadata?: { category?: string; confidence?: string };
    };
}

interface SemgrepPayload {
    results?: SemgrepResult[];
    errors?: unknown[];
    paths?: { scanned?: string[] };
}

export class SastScanner {
    constructor(private readonly runner = new ContainerRunner()) {}

    /** Rend les constats, ou `null` si l'analyse n'a pas réellement eu lieu. */
    async scan(workspace: Workspace, subPath = ''): Promise<SastFinding[] | null> {
        const target = subPath ? posix.join('/repo', SOURCE_SUBDIR, subPath) : posix.join('/repo', SOURCE_SUBDIR);
        // `rules/semgrep`, et non `rules` : l'espace de travail porte désormais aussi la
    // configuration de gitleaks, et pointer Semgrep sur le répertoire parent lui ferait
    // parcourir un arbre qui n'est pas le sien.
    const rules = posix.join('/repo', RULES_SUBDIR, 'semgrep');
        const label = 'semgrep (analyse du code source)';

        try {
            const result = await this.runner.run({
                image: SEMGREP_IMAGE,
                command: [
                    'semgrep',
                    'scan',
                    `--config=${rules}`,
                    '--no-rewrite-rule-ids',
                    // **La cible ne choisit pas ce qu'on regarde.** Semgrep honore par
                    // défaut le `.gitignore` de l'arbre analysé — qui est un clone du dépôt
                    // scanné, donc écrit par qui on audite. Un `*` committé excluait tout,
                    // et l'étape rendait un succès vide.
                    '--no-git-ignore',
                    '--json',
                    '--metrics=off',
                    '--disable-version-check',
                    '--quiet',
                    '--timeout=30',
                    '--timeout-threshold=3',
                    '--max-target-bytes=1000000',
                    '--max-memory=1500',
                    '--jobs=2',
                    target
                ],
                binds: [{ source: workspace.root, target: '/repo', readOnly: true }],
                label,
                network: false,
                asRoot: true
            });

            const payload = parseScannerJson<SemgrepPayload>(result, label);
            if (payload === null) return null;
            if (mostlyFailed(payload)) return null;

            return (payload.results ?? []).map((entry) => toSastFinding(entry, subPath));
        } catch {
            // Couvre aussi l'expiration, levée par l'attente du conteneur et non par la
            // lecture : Semgrep est le premier scanner pour lequel le délai global est un
            // résultat normal plausible sur un gros dépôt, et une exécution expirée ne sait
            // rien du code.
            return null;
        }
    }
}

/**
 * L'analyse a-t-elle échoué sur assez de fichiers pour ne rien valoir ?
 *
 * Le rapport porte ses propres erreurs et la liste des fichiers réellement analysés ; le
 * code de retour, lui, ne dit rien. Sans cette lecture, un dépôt dont quatre fichiers sur
 * cinq ont expiré se lirait « analysé, presque rien trouvé ».
 */
function mostlyFailed(payload: SemgrepPayload): boolean {
    const errors = payload.errors?.length ?? 0;
    const scanned = payload.paths?.scanned?.length ?? 0;

    // **Zéro fichier examiné n'est pas un arbre propre, c'est une analyse qui n'a pas eu
    // lieu** — et c'était le trou. Le test sortait sur `errors === 0` avant de regarder la
    // couverture, si bien qu'une exécution ayant tout exclu rendait `[]`, donc « analysé,
    // rien trouvé », donc la résolution de tout le backlog SAST et qualité de la cible.
    //
    // La sélection des fichiers est influençable depuis le dépôt : Semgrep honore
    // `.semgrepignore` et, par défaut, `.gitignore` — et l'arbre est toujours un clone git.
    // Un `*` committé suffisait à éteindre l'étape en la faisant passer pour un succès.
    if (scanned === 0) return true;

    if (errors === 0) return false;
    return errors / (errors + scanned) > MAX_ERROR_RATIO;
}

function toSastFinding(entry: SemgrepResult, subPath: string): SastFinding {
    const extra = entry.extra ?? {};
    const prefix = subPath ? `/repo/${SOURCE_SUBDIR}/${subPath}` : `/repo/${SOURCE_SUBDIR}`;
    return {
        ruleId: entry.check_id ?? 'inconnu',
        // Absente, la catégorie vaut « security » : c'est la lecture prudente. Classer un
        // constat inconnu en qualité le rendrait incapable de faire échouer un gate.
        category: extra.metadata?.category ?? 'security',
        severity: mapSeverity(extra.severity),
        confidence: extra.metadata?.confidence ?? null,
        file: (entry.path ?? '').replace(prefix, '').replace(/^\/+/, ''),
        line: entry.start?.line ?? 0,
        message: extra.message ?? ''
    };
}

/**
 * Le vocabulaire de Semgrep vers celui de Zanshin.
 *
 * Table explicite et non `toLowerCase()` : `"ERROR".toLowerCase()` donne `error`, qui
 * n'appartient à aucun seuil de politique. La valeur se propagerait alors en silence
 * jusqu'au tri, au résumé, au gate et à l'export SARIF.
 */
function mapSeverity(severity: string | undefined): string {
    switch (severity) {
        case 'ERROR':
            return 'high';
        case 'WARNING':
            return 'medium';
        case 'INFO':
            return 'low';
        default:
            return 'medium';
    }
}
