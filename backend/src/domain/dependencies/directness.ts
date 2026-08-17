/**
 * Which dependencies the project actually asked for.
 *
 * Every vulnerability used to arrive with the same amount of information about *what to do*:
 * none. A critical CVE in a package declared in the manifest is fixed this afternoon by
 * changing one line; the same CVE four levels down, pulled in by something else, waits on an
 * upstream release and may need a pin, a fork, or the decision to accept the risk. Ranked
 * identically, they produce a backlog nobody finishes — and the transitive ones, being the
 * majority, bury the handful that are actionable today.
 *
 * **Syft already answers this question and the answer was being thrown away.** The SBOM
 * carries `dependency-of` relationships, where the *parent* is the dependency and the
 * *child* is what depends on it. A package that never appears as a parent is therefore a
 * root of the graph: exactly "the project declared this".
 *
 * **The important part is what happens when the graph is absent.** Some catalogers emit no
 * edges at all, and then *every* package looks like a root — which would label a whole image
 * "direct dependencies". That is worse than saying nothing: it is a confident wrong answer
 * on the very field meant to decide what to fix first. An empty graph therefore returns
 * `null` — unknown — everywhere.
 */

const DEPENDENCY_OF = 'dependency-of';

/** `true` direct, `false` transitive, `null` unknown. */
export type Directness = boolean | null;

export class DependencyDirectness {
    private readonly byPurl = new Map<string, boolean>();
    private readonly byNameVersion = new Map<string, boolean>();

    /** Did the graph carry any edges? If not, everything is unknown. */
    readonly available: boolean;

    constructor(sbom: Record<string, unknown> | null) {
        const artifacts = (sbom?.artifacts ?? []) as Record<string, unknown>[];
        const relationships = (sbom?.artifactRelationships ?? []) as Record<string, unknown>[];

        if (!Array.isArray(artifacts) || artifacts.length === 0) {
            this.available = false;
            return;
        }

        const dependedUpon = new Set<string>();
        if (Array.isArray(relationships)) {
            for (const relation of relationships) {
                if (relation.type === DEPENDENCY_OF && typeof relation.parent === 'string' && relation.parent) {
                    dependedUpon.add(relation.parent);
                }
            }
        }

        if (dependedUpon.size === 0) {
            this.available = false;
            return;
        }
        this.available = true;

        for (const artifact of artifacts) {
            const isDirect = typeof artifact.id === 'string' ? !dependedUpon.has(artifact.id) : false;

            // A purl already carries the version, so two versions of the same package keep
            // distinct answers — which matters, because one may be declared and the other
            // dragged in by something else.
            if (typeof artifact.purl === 'string' && artifact.purl) {
                this.byPurl.set(artifact.purl, (this.byPurl.get(artifact.purl) ?? false) || isDirect);
            }
            if (typeof artifact.name === 'string' && artifact.name) {
                const key = `${artifact.name}@${artifact.version ?? ''}`;
                this.byNameVersion.set(key, (this.byNameVersion.get(key) ?? false) || isDirect);
            }
        }
    }

    /**
     * The answer for one package.
     *
     * **The purl first**: it is the ecosystem-qualified identity, and it is what Grype's
     * matches and the license findings carry. The name+version pair is the fallback for a
     * cataloger that produced no purl; matching on the name alone is **deliberately not
     * attempted**, since two versions of the same package can fall on either side of this
     * answer.
     */
    of(purl?: string | null, name?: string | null, version?: string | null): Directness {
        if (!this.available) return null;

        if (purl && this.byPurl.has(purl)) return this.byPurl.get(purl)!;
        if (name) {
            const key = `${name}@${version ?? ''}`;
            if (this.byNameVersion.has(key)) return this.byNameVersion.get(key)!;
        }
        return null;
    }

    /** How many packages are direct — for the log, and for reassurance about the graph. */
    get directCount(): number {
        return [...this.byPurl.values()].filter(Boolean).length;
    }
}
