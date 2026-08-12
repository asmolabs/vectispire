import { posix } from 'node:path';
import { ContainerRunner, parseScannerJson } from '../container-runner';
import { SOURCE_SUBDIR, type Workspace } from '../workspace';
import { CHECKOV_IMAGE } from './images';

/**
 * L'analyse des manifestes d'infrastructure — Terraform, Kubernetes, Dockerfile.
 *
 * **Rend `null` et jamais `[]` quand checkov échoue.** La distinction est celle qui décide
 * du sort du backlog : `[]` signifie « analysé, propre », ce que l'ingestion lit comme
 * l'autorisation de résoudre chaque problème IaC de la cible. Un plantage de checkov
 * déclarerait donc un dépôt corrigé. `null` dit que rien n'a été regardé, et le backlog
 * est laissé tranquille.
 *
 * Cette prudence n'est pas théorique : le comportement de checkov en ligne de commande et
 * sa sortie varient selon la version et selon les cadres détectés, et un échec ici ne doit
 * pas couler tout le scan.
 */

/** Un contrôle en échec, réduit à ce que Zanshin en garde. */
export interface IacFinding {
    /** L'identifiant du contrôle — `CKV_AWS_20` et consorts. */
    checkId: string;
    /** Ce que le contrôle vérifie, en clair. */
    checkName: string;
    file: string;
    line: number;
    /** Le lien vers la documentation du contrôle, quand checkov en donne un. */
    guideline: string | null;
    /** La ressource concernée : `aws_s3_bucket.exemple`. */
    resource: string | null;
}

interface CheckovCheck {
    check_id?: string;
    check_name?: string;
    file_path?: string;
    file_line_range?: number[];
    guideline?: string | null;
    resource?: string;
}

interface CheckovReport {
    results?: { failed_checks?: CheckovCheck[] };
}

export class IacScanner {
    constructor(private readonly runner = new ContainerRunner()) {}

    async scan(workspace: Workspace, subPath = ''): Promise<IacFinding[] | null> {
        const target = subPath ? posix.join('/repo', SOURCE_SUBDIR, subPath) : posix.join('/repo', SOURCE_SUBDIR);
        const label = 'checkov (analyse IaC)';

        try {
            const result = await this.runner.run({
                image: CHECKOV_IMAGE,
                // `--soft-fail` : checkov sort en 1 quand un contrôle échoue. Ici c'est le
                // résultat attendu, pas un échec de conteneur — même raison que
                // `--exit-code=0` pour gitleaks.
                command: ['-d', target, '-o', 'json', '--soft-fail', '--compact'],
                binds: [{ source: workspace.root, target: '/repo', readOnly: true }],
                label,
                network: false,
                asRoot: true
            });

            const payload = parseScannerJson<CheckovReport | CheckovReport[]>(result, label);
            if (payload === null) return null;

            // checkov rend **un** objet de rapport quand un seul cadre est détecté, et une
            // *liste* quand plusieurs le sont — Terraform et Kubernetes dans le même dépôt,
            // par exemple. Traiter les deux formes est ce qui évite qu'un dépôt mixte ne
            // rende rien.
            const reports = Array.isArray(payload) ? payload : [payload];
            return reports.flatMap((report) => report.results?.failed_checks ?? []).map((check) => toIacFinding(check, subPath));
        } catch {
            // Volontairement large : la sortie de checkov varie assez d'une version à
            // l'autre pour qu'un échec soit plausible sans que le reste du scan ait à en
            // souffrir. `null` — jamais `[]` — pour la raison exposée en tête de fichier.
            return null;
        }
    }
}

function toIacFinding(check: CheckovCheck, subPath: string): IacFinding {
    const prefix = subPath ? `/repo/${SOURCE_SUBDIR}/${subPath}` : `/repo/${SOURCE_SUBDIR}`;
    return {
        checkId: check.check_id ?? 'inconnu',
        checkName: check.check_name ?? '',
        // checkov rend un chemin relatif à sa cible, parfois préfixé d'une barre. Les deux
        // formes sont ramenées à un chemin relatif à l'arbre scanné, sans quoi le même
        // fichier porterait deux identités selon la version.
        file: (check.file_path ?? '').replace(prefix, '').replace(/^\/+/, ''),
        line: check.file_line_range?.[0] ?? 0,
        guideline: check.guideline ?? null,
        resource: check.resource ?? null
    };
}
