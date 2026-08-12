import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

/**
 * L'espace de travail d'un scan : un répertoire éphémère, et sa disposition.
 *
 * **Le répertoire scanné est un sous-répertoire, pas la racine.** Tout artefact que
 * Zanshin produit lui-même — le SBOM pour Grype, le rapport gitleaks — atterrit à la
 * racine, donc délibérément *hors* de l'arbre analysé.
 *
 * La séparation est structurelle plutôt qu'une liste de fichiers à ignorer, parce que
 * deux de ces artefacts sont activement nuisibles à réinjecter : le rapport gitleaks
 * contient **chaque secret détecté en clair**, et un SBOM Syft dépasse à lui seul le
 * budget d'une revue par modèle. Garder la cible dans son propre répertoire fait que rien
 * qui parcourt l'arbre source ne peut les atteindre, quoi qu'on ajoute plus tard.
 *
 * **Les règles sont copiées dans l'espace de travail** plutôt que lues sur place. Cela
 * ressemble à un détour — elles existent déjà à côté de ce module — mais c'est le seul
 * emplacement qui fonctionne partout : les chemins de volume sont résolus par le *démon*
 * Docker, pas par le processus qui l'appelle. Quand Zanshin tourne lui-même dans un
 * conteneur avec la socket montée, un répertoire de son image est invisible du conteneur
 * frère. L'espace de travail est le seul chemin que les deux côtés voient.
 */

/** Le sous-répertoire qui contient **uniquement** la cible du scan. */
export const SOURCE_SUBDIR = 'source';

/** Frère du précédent, portant l'arbre de règles pour la durée du scan. */
export const RULES_SUBDIR = 'rules';

export interface Workspace {
    /** La racine, où atterrissent les artefacts que Zanshin produit. */
    readonly root: string;
    /** L'arbre cloné. Rien d'autre n'y est écrit. */
    readonly source: string;
    /** Les règles copiées pour ce scan. */
    readonly rules: string;
}

/**
 * Crée un espace de travail et le confie à `body`, en garantissant sa suppression.
 *
 * La suppression est dans un `finally` et non après l'appel : un scan qui échoue laisse
 * derrière lui un arbre cloné, parfois volumineux, et souvent le rapport gitleaks qui
 * contient les secrets trouvés. Les échecs sont précisément le cas où l'on oublie de
 * nettoyer, et le seul où cela compte vraiment.
 */
export async function withWorkspace<T>(body: (workspace: Workspace) => Promise<T>): Promise<T> {
    // `mkdtemp` et non un nom construit : le suffixe aléatoire du système évite qu'un
    // second scan de la même cible écrase le premier, et le répertoire naît en 0700.
    const root = await mkdtemp(join(tmpdir(), 'zanshin-scan-'));
    const workspace: Workspace = {
        root,
        source: join(root, SOURCE_SUBDIR),
        rules: join(root, RULES_SUBDIR)
    };

    try {
        return await body(workspace);
    } finally {
        // `force` : l'absence du répertoire n'est pas une erreur, et lever ici masquerait
        // l'exception d'origine — celle qui explique pourquoi le scan a échoué.
        await rm(root, { recursive: true, force: true });
    }
}
