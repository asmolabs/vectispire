import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, posix } from 'node:path';
import { ContainerRunner, parseScannerJson } from '../container-runner';
import { SOURCE_SUBDIR, type Workspace } from '../workspace';
import { GRYPE_IMAGE, SYFT_IMAGE } from './images';

/**
 * L'analyse des dépendances, en deux temps : Syft dresse l'inventaire, Grype le confronte
 * aux vulnérabilités connues.
 *
 * **Deux outils et non un** parce que le SBOM a une valeur propre : il est exportable, il
 * répond à « qu'y a-t-il dans cette application », et il permet de rejouer l'analyse de
 * vulnérabilités sans re-parcourir le code. Fusionner les deux étapes ferait perdre cet
 * artefact.
 *
 * **Le réseau est ouvert pour Grype seulement.** Syft, sur un répertoire, lit des fichiers
 * de dépendances et n'a rien à aller chercher. Grype télécharge et rafraîchit sa base de
 * vulnérabilités : sans réseau, il travaillerait sur une base absente ou périmée et
 * rendrait un résultat rassurant sans le dire.
 */

const SBOM_FILENAME = 'sbom.json';

/**
 * L'architecture auditée par défaut.
 *
 * Explicite, parce que le démon rendrait sinon celle de l'hôte : une machine de
 * développement arm64 produirait le SBOM d'une image arm64 alors que la production
 * déploie du linux/amd64, et les vulnérabilités trouvées ne seraient pas celles qui
 * comptent.
 */
export const DEFAULT_PLATFORM = process.env.ZANSHIN_IMAGE_SCAN_PLATFORM ?? 'linux/amd64';

/** Le SBOM tel que Syft le rend. Traité comme opaque : il est stocké et réexporté tel quel. */
export type Sbom = Record<string, unknown>;

/** Un composant vulnérable, réduit à ce que Zanshin en garde. */
export interface DependencyFinding {
    /** L'identifiant de la vulnérabilité — CVE, GHSA, ou ce que la source emploie. */
    identifier: string;
    severity: string;
    packageName: string;
    installedVersion: string;
    /** Les versions qui corrigent, séparées par des virgules. Vide si aucune n'existe. */
    fixVersions: string;
    description: string | null;
    /** L'URL de référence la plus utile, quand la source en donne une. */
    referenceUrl: string | null;
    /** L'identifiant de paquet universel : ce qui permet de recouper deux sources. */
    purl: string | null;
}

interface GrypeMatch {
    vulnerability?: {
        id?: string;
        severity?: string;
        description?: string;
        dataSource?: string;
        fix?: { versions?: string[] };
    };
    artifact?: { name?: string; version?: string; purl?: string };
}

export class DependencyScanner {
    constructor(private readonly runner = new ContainerRunner()) {}

    /**
     * Dresse l'inventaire des dépendances d'un répertoire.
     *
     * Monté en lecture seule : Syft n'a aucune raison d'écrire dans l'arbre analysé, et le
     * lui interdire élimine la question de savoir s'il le fait.
     */
    async generateSbom(workspace: Workspace, subPath = ''): Promise<Sbom | null> {
        const target = subPath ? posix.join('/src', SOURCE_SUBDIR, subPath) : posix.join('/src', SOURCE_SUBDIR);
        const label = 'syft (SBOM du répertoire)';

        const result = await this.runner.run({
            image: SYFT_IMAGE,
            command: [`dir:${target}`, '-o', 'json'],
            binds: [{ source: workspace.root, target: '/src', readOnly: true }],
            label,
            network: false,
            asRoot: true
        });

        return parseScannerJson<Sbom>(result, label);
    }

    /**
     * Dresse l'inventaire d'une **image de conteneur**.
     *
     * **C'est la seule étape qui monte la socket Docker, et elle équivaut à root sur
     * l'hôte.** Rien dans le durcissement du conteneur ne change cela : qui parle à la
     * socket peut démarrer un conteneur privilégié. Le prix est assumé pour scanner des
     * images, et c'est la raison pour laquelle il existe un backend qui retire la socket
     * entièrement.
     *
     * `docker:` et non `registry:` : le client de registre de Syft tronque les
     * téléchargements de couches multi-architecture — « unable to populate layer cache …
     * unexpected EOF » — ce qui faisait échouer chaque scan de conteneur sur un hôte arm64
     * auditant une image linux/amd64. Passer par le démon corrige cela et réutilise
     * l'image déjà présente localement au lieu de la retélécharger à chaque scan.
     *
     * `--platform` reste **obligatoire** : sans lui le démon rend l'architecture de
     * l'*hôte*, produisant en silence le SBOM d'une variante que personne n'a demandé
     * d'auditer.
     */
    async generateSbomForImage(reference: string, platform = DEFAULT_PLATFORM): Promise<Sbom | null> {
        const label = `syft (SBOM de l'image ${reference})`;
        const result = await this.runner.run({
            image: SYFT_IMAGE,
            command: [`docker:${reference}`, '--platform', platform, '-o', 'json'],
            binds: [],
            label,
            // Tire par le démon, et peut atteindre le registre.
            network: true,
            dockerSocket: true,
            asRoot: true
        });

        return parseScannerJson<Sbom>(result, label);
    }

    /**
     * Confronte un SBOM aux vulnérabilités connues.
     *
     * Le SBOM passe par un fichier de l'espace de travail plutôt que par l'entrée standard :
     * c'est ce que Grype attend, et cela laisse l'artefact disponible pour l'export.
     *
     * **Rend `null` quand l'analyse n'a pas eu lieu**, jamais une liste vide. Une liste vide
     * signifie « analysé, aucune vulnérabilité » et résout tout le backlog de la cible —
     * ce qui, après un échec de téléchargement de la base, serait un mensonge coûteux.
     */
    async scanSbom(workspace: Workspace, sbom: Sbom): Promise<DependencyFinding[] | null> {
        const sbomPath = join(workspace.root, SBOM_FILENAME);
        await writeFile(sbomPath, JSON.stringify(sbom));

        const label = 'grype (analyse du SBOM)';
        const result = await this.runner.run({
            image: GRYPE_IMAGE,
            command: ['sbom:/work/' + SBOM_FILENAME, '-o', 'json'],
            binds: [{ source: workspace.root, target: '/work', readOnly: true }],
            label,
            // Grype télécharge et rafraîchit sa base de vulnérabilités.
            network: true,
            asRoot: true
        });

        const parsed = parseScannerJson<{ matches?: GrypeMatch[] }>(result, label);
        if (parsed === null) return null;
        return (parsed.matches ?? []).map(toDependencyFinding);
    }

    /**
     * L'appariement d'un SBOM qui ne vient pas d'un arbre cloné — celui d'une image.
     *
     * Le SBOM est écrit dans un répertoire temporaire à lui, parce que Grype le lit depuis
     * un montage : il n'y a pas d'espace de travail de scan à réutiliser ici, et en créer
     * un complet pour un seul fichier reviendrait à préparer un clone qui n'aura pas lieu.
     *
     * Le répertoire est retiré dans tous les cas, y compris en cas d'échec : un SBOM
     * d'image pèse plusieurs mégaoctets, et un scan qui échoue toutes les heures
     * remplirait le disque sans que personne ne fasse le lien.
     */
    async scanSbomStandalone(sbom: Sbom): Promise<DependencyFinding[] | null> {
        const directory = await mkdtemp(join(tmpdir(), 'zanshin-sbom-'));
        try {
            await writeFile(join(directory, SBOM_FILENAME), JSON.stringify(sbom));

            const label = "grype (analyse du SBOM d'image)";
            const result = await this.runner.run({
                image: GRYPE_IMAGE,
                command: ['sbom:/work/' + SBOM_FILENAME, '-o', 'json'],
                binds: [{ source: directory, target: '/work', readOnly: true }],
                label,
                network: true,
                asRoot: true
            });

            const parsed = parseScannerJson<{ matches?: GrypeMatch[] }>(result, label);
            if (parsed === null) return null;
            return (parsed.matches ?? []).map(toDependencyFinding);
        } finally {
            await rm(directory, { recursive: true, force: true });
        }
    }
}

function toDependencyFinding(match: GrypeMatch): DependencyFinding {
    const vulnerability = match.vulnerability ?? {};
    const artifact = match.artifact ?? {};
    return {
        identifier: vulnerability.id ?? 'inconnu',
        // Minuscules : le vocabulaire de sévérité de Zanshin l'est, et « High » venu de
        // Grype ne correspondrait à aucun seuil de politique — le constat serait créé et
        // n'entrerait dans aucun gate.
        severity: (vulnerability.severity ?? 'unknown').toLowerCase(),
        packageName: artifact.name ?? 'inconnu',
        installedVersion: artifact.version ?? '',
        // Chaîne et non tableau : `fixVersions` sert de drapeau « corrigeable » dans le
        // gate, où une chaîne vide vaut « aucun correctif ». Un tableau vide et `null` s'y
        // comporteraient différemment selon le chemin.
        fixVersions: (vulnerability.fix?.versions ?? []).join(', '),
        description: vulnerability.description ?? null,
        referenceUrl: vulnerability.dataSource ?? null,
        purl: artifact.purl ?? null
    };
}
