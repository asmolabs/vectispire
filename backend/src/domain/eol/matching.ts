/**
 * Matching a version to its life cycle, and the verdict that follows.
 *
 * Pure functions: everything that can genuinely go wrong here — a version prefix compared
 * wrongly, a date read askew, a purl carrying its architecture — is testable with no
 * network. The service calling them only fetches the documents and caches them.
 */

/** A product release, as endoflife.date publishes it. */
export interface Release {
    name?: string;
    eolFrom?: string | null;
    isEol?: boolean;
    isMaintained?: boolean;
    latest?: { name?: string } | null;
}

export interface Product {
    name?: string;
    releases?: Release[];
}

/** The default warning window, in days. */
export const DEFAULT_WARN_DAYS = 180;

/**
 * `pkg:type/namespace/name`, with no version and no qualifiers.
 *
 * A SBOM purl carries both (`pkg:rpm/redhat/openssl@3.5.1?arch=x86_64`) where the catalog's
 * identifiers carry neither: both sides are therefore reduced to what names the **product**
 * rather than the build.
 */
export function normalizePurl(purl: string): string {
    let value = (purl ?? '').trim();
    for (const separator of ['?', '#']) value = value.split(separator, 1)[0];
    const at = value.lastIndexOf('@');
    if (at > 0) value = value.slice(0, at);
    return value.toLowerCase().replace(/\/+$/, '');
}

/**
 * A version's numeric components, stopping at the first one that is not numeric.
 *
 * `"9.7 (Plow)"` becomes `['9','7']` and `"3.12.1-rc1"` becomes `['3','12','1']`: neither a
 * distribution's decorated version nor a package's build suffix must stop the cycle from
 * being recognized.
 */
export function versionParts(version: string): string[] {
    const cleaned = (version ?? '').trim().split(' ')[0];
    const parts: string[] = [];

    for (const chunk of cleaned.split('.')) {
        const digits = /^\d+/.exec(chunk)?.[0] ?? '';
        if (!digits) break;
        parts.push(digits);
    }
    return parts;
}

/**
 * The cycle a version belongs to.
 *
 * **Compared component by component, never by string prefix**: "3.14" starts with "3.1", so
 * a `startsWith` would file Python 3.14 under the 3.1 cycle and announce a support window
 * that closed years ago. The longest matching cycle wins, so that a product publishing both
 * "8" and "8.1" resolves correctly.
 */
export function matchRelease(product: Product, version: string): Release | null {
    const wanted = versionParts(version);
    let best: Release | null = null;
    let bestLength = -1;

    for (const release of product.releases ?? []) {
        const parts = versionParts(String(release.name ?? ''));
        if (parts.length === 0 || parts.length > wanted.length) continue;
        if (parts.every((part, index) => wanted[index] === part) && parts.length > bestLength) {
            best = release;
            bestLength = parts.length;
        }
    }
    return best;
}

/** The verdict on a cycle: its severity, or `null` if it is comfortably supported. */
export interface Verdict {
    severity: 'high' | 'medium';
    eolDate: Date | null;
}

/**
 * Assesses a cycle at a given date.
 *
 * **A cycle already past its end is `high`** — not because something is broken today, but
 * because nothing will be fixed tomorrow, which is not a "medium" for a component you ship.
 * An end date still ahead is `medium`: a deadline, not an incident.
 *
 * Beyond the window, nothing is reported: everything reaches end of life one day, and
 * flagging a version supported for another three years would teach people to filter this
 * type out.
 */
export function assess(release: Release, today: Date, warnDays: number = DEFAULT_WARN_DAYS): Verdict | null {
    const eolDate = parseDate(release.eolFrom);

    if (release.isEol === true || (eolDate && eolDate <= today)) return { severity: 'high', eolDate };

    if (eolDate) {
        const daysLeft = Math.floor((eolDate.getTime() - today.getTime()) / 86_400_000);
        if (daysLeft >= 0 && daysLeft <= warnDays) return { severity: 'medium', eolDate };
    }

    // `isMaintained: false` with no date: the abandoned-product case.
    if (release.isMaintained === false && !eolDate) return { severity: 'high', eolDate: null };

    return null;
}

/**
 * The most recent maintained release — that is, what "fix this" means here.
 *
 * Placed on `fixVersions` so an end-of-life finding reads like every other actionable
 * finding, on screen as in the exports.
 */
export function recommendedVersion(product: Product): string | null {
    for (const release of product.releases ?? []) {
        if (release.isMaintained && !release.isEol) return release.latest?.name || String(release.name ?? '') || null;
    }
    return null;
}

/** An ISO date from the catalog, or `null`. Returned in UTC to stay comparable. */
export function parseDate(value: unknown): Date | null {
    if (typeof value !== 'string' || value.length < 10) return null;
    const parsed = new Date(`${value.slice(0, 10)}T00:00:00Z`);
    return Number.isNaN(parsed.getTime()) ? null : parsed;
}

/** The purl → product index, read from the catalog's response. */
export function parseIdentifierIndex(payload: unknown): Map<string, string> {
    const index = new Map<string, string>();
    const result = (payload as { result?: unknown })?.result;
    if (!Array.isArray(result)) return index;

    for (const entry of result) {
        const identifier = (entry as { identifier?: unknown })?.identifier;
        const product = ((entry as { product?: { name?: unknown } })?.product?.name ?? '') as string;
        if (typeof identifier === 'string' && identifier && typeof product === 'string' && product.trim()) {
            index.set(normalizePurl(identifier), product.trim());
        }
    }
    return index;
}

/** What a SBOM offers the lookup: product, version, label, purl. */
export interface Candidate {
    product: string;
    version: string;
    label: string;
    purl: string | null;
}

/**
 * The SBOM packages that match a product in the catalog.
 *
 * The distribution is handled separately by the service: a Syft SBOM carries **no purl for
 * the operating system itself**, even though that is the most useful answer for a container
 * image — the one no package-level lookup would find.
 */
export function packageCandidates(sbom: Record<string, unknown>, index: Map<string, string>): Candidate[] {
    const artifacts = sbom.artifacts;
    if (!Array.isArray(artifacts) || index.size === 0) return [];

    const candidates: Candidate[] = [];
    for (const artifact of artifacts) {
        const purl = (artifact as { purl?: unknown })?.purl;
        const version = String((artifact as { version?: unknown })?.version ?? '').trim();
        if (typeof purl !== 'string' || !purl || !version) continue;

        const product = index.get(normalizePurl(purl));
        if (!product) continue;

        candidates.push({ product, version, label: String((artifact as { name?: unknown })?.name ?? product), purl });
    }
    return candidates;
}

/** An image's distribution, read from the SBOM's `distro` block. */
export function distroCandidate(sbom: Record<string, unknown>): { id: string; version: string; label: string } | null {
    const distro = (sbom.distro ?? {}) as Record<string, unknown>;
    const id = String(distro.id ?? '').trim().toLowerCase();
    const version = String(distro.versionID ?? '').trim();
    if (!id || !version) return null;

    return { id, version, label: String(distro.name ?? id) };
}
