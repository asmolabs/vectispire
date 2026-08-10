import { createHash } from 'node:crypto';

/**
 * L'identité d'un problème à travers les scans.
 *
 * **Le contrat de données le plus critique du système.** Deux scans successifs
 * produisent des constats bruts sans identité ; c'est cette empreinte qui décide si
 * ce que le scanner vient de voir est *le même problème qu'hier* — avec son
 * historique, son nombre d'occurrences et surtout sa décision de triage — ou un
 * problème neuf.
 *
 * Une divergence d'un seul octet avec l'implémentation Python n'échoue nulle part :
 * elle fait qu'aucune empreinte calculée ici ne correspond à celles déjà en base. Au
 * premier scan après la bascule, tout le backlog existant serait résolu (« ces
 * problèmes ne sont plus vus ») et recréé à neuf, **triage perdu** — chaque décision
 * `not_affected` argumentée, chaque justification VEX, chaque échéance de réexamen.
 * Sans erreur, sans journal, avec un tableau de bord d'apparence normale.
 *
 * D'où `test/vectors/issue-fingerprint.json`, généré depuis le code Python.
 *
 * ## Ce qui entre, et ce qui n'entre pas
 *
 * `SHA-256("repo:{id}|{type}|{identifier}|{purl ou nom}|{chemin}")`
 *
 * Sont **délibérément exclus** :
 *
 * - **la version du paquet.** Une dépendance obsolète qui le reste à travers trois
 *   montées de version est un problème avec un historique, pas trois problèmes
 *   distincts — et une décision de triage s'évaporerait à chaque correctif ;
 * - **le caractère direct ou transitif** de la dépendance : une dépendance qui passe
 *   de directe à transitive reste le même problème vu autrement ;
 * - **le numéro de ligne** : un secret qui descend de trois lignes reste le même secret.
 *
 * Le `purl` prime sur le nom de paquet parce qu'il est l'identité qualifiée par
 * écosystème ; le repli sur le nom garde empreintables les constats qui n'ont pas de
 * purl — secrets, IaC, licences.
 *
 * ## Une faiblesse reproduite volontairement
 *
 * Le séparateur est une barre verticale, et non l'octet NUL de la chaîne d'audit. Un
 * chemin de fichier contenant `|` peut donc, en principe, imiter une frontière de
 * champ et produire une collision. **Ne corrigez pas ceci ici.** Changer le
 * séparateur changerait toutes les empreintes déjà stockées, ce qui est exactement le
 * scénario décrit plus haut. Si cela doit être corrigé un jour, ce sera par une
 * migration qui recalcule les empreintes en base dans la même transaction.
 */
export interface FingerprintInput {
    /** Exclusif avec `containerId` : un problème appartient à une cible. */
    repoId: number | null;
    containerId: number | null;
    findingType: string | null;
    identifier: string | null;
    purl: string | null;
    packageName: string | null;
    filePath: string | null;
}

export function buildFingerprint(input: FingerprintInput): string {
    // `repo_id is not None` en Python : c'est bien la présence qui décide, pas la
    // véracité. Un `repoId` valant 0 désigne le dépôt 0, pas l'absence de dépôt —
    // d'où `!= null` et non un test de vérité, qui rangerait ce cas côté conteneur.
    const target = input.repoId != null ? `repo:${input.repoId}` : `container:${input.containerId}`;

    const parts = [
        target,
        input.findingType || '',
        input.identifier || '',
        // `purl or package_name or ""` : chaîne vide et null se comportent pareil,
        // comme en Python. Un purl vide retombe donc sur le nom de paquet.
        input.purl || input.packageName || '',
        input.filePath || ''
    ];

    return createHash('sha256').update(parts.join('|'), 'utf8').digest('hex');
}
