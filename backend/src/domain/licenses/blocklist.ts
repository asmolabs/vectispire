/**
 * Les licences interdites, lues du SBOM que Syft produit déjà.
 *
 * **Aucun nouvel outil n'est nécessaire** : Syft enregistre les licences de chaque
 * composant dans le SBOM de tout scan, image ou répertoire. Ceci n'est donc que
 * l'évaluation d'une règle sur une donnée déjà collectée.
 *
 * **Rien n'est signalé tant qu'aucune liste n'est configurée.** Quelles licences sont
 * interdites est une décision d'organisation, pas une décision technique : un défaut
 * imposerait un jugement juridique à la place de l'opérateur.
 */

/** Un composant du SBOM, réduit à ce que la règle regarde. */
export interface SbomArtifact {
    name?: string;
    version?: string;
    purl?: string;
    licenses?: unknown;
}

export interface LicenseViolation {
    license: string;
    packageName: string | null;
    packageVersion: string | null;
    purl: string | null;
}

/** La liste, normalisée en majuscules pour une comparaison insensible à la casse. */
export function parseBlocklist(raw: string): Set<string> {
    return new Set(
        (raw ?? '')
            .split(',')
            .map((entry) => entry.trim().toUpperCase())
            .filter((entry) => entry !== '')
    );
}

/**
 * Les licences d'un composant.
 *
 * Syft a représenté les licences **à la fois comme des chaînes et, dans les versions plus
 * récentes de son schéma, comme des objets** (`{"value": "MIT", "spdxExpression": "MIT"}`).
 * Les deux sont traitées : ne gérer qu'une forme ferait taire la règle à la prochaine
 * montée de version de Syft — sans erreur, et sans que personne ne s'en aperçoive.
 */
export function extractLicenses(artifact: SbomArtifact): string[] {
    const entries = artifact.licenses;
    if (!Array.isArray(entries)) return [];

    const values: string[] = [];
    for (const entry of entries) {
        if (typeof entry === 'string' && entry.trim()) {
            values.push(entry);
        } else if (typeof entry === 'object' && entry !== null) {
            const record = entry as Record<string, unknown>;
            const value = record.value ?? record.spdxExpression;
            if (typeof value === 'string' && value.trim()) values.push(value);
        }
    }
    return values;
}

/** Les composants dont une licence figure sur la liste. */
export function findViolations(sbom: Record<string, unknown>, blocklist: Set<string>): LicenseViolation[] {
    if (blocklist.size === 0) return [];

    const artifacts = sbom.artifacts;
    if (!Array.isArray(artifacts)) return [];

    const violations: LicenseViolation[] = [];
    for (const artifact of artifacts as SbomArtifact[]) {
        for (const license of extractLicenses(artifact)) {
            if (!blocklist.has(license.toUpperCase())) continue;
            violations.push({
                license,
                packageName: artifact.name ?? null,
                packageVersion: artifact.version ?? null,
                purl: artifact.purl ?? null
            });
        }
    }
    return violations;
}
