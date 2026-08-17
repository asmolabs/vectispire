/**
 * The forbidden licenses, read from the SBOM Syft already produces.
 *
 * **No new tool is needed**: Syft records every component's licenses in the SBOM of any
 * scan, image or directory. This is therefore only the evaluation of a rule over data
 * already collected.
 *
 * **Nothing is reported until a list is configured.** Which licenses are forbidden is an
 * organizational decision, not a technical one: a default would impose a legal judgement in
 * the operator's place.
 */

/** A SBOM component, reduced to what the rule looks at. */
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

/** The list, upper-cased for a case-insensitive comparison. */
export function parseBlocklist(raw: string): Set<string> {
    return new Set(
        (raw ?? '')
            .split(',')
            .map((entry) => entry.trim().toUpperCase())
            .filter((entry) => entry !== '')
    );
}

/**
 * A component's licenses.
 *
 * Syft has represented licenses **both as strings and, in more recent versions of its
 * schema, as objects** (`{"value": "MIT", "spdxExpression": "MIT"}`). Both are handled:
 * supporting only one shape would silence the rule at Syft's next version bump — with no
 * error, and with nobody noticing.
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

/** The components one of whose licenses is on the list. */
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
