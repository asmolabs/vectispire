/**
 * The reading of the two public exploitation catalogs: EPSS and CISA KEV.
 *
 * Pure functions, kept apart from the service that calls the network — that is what makes
 * the part which can genuinely go wrong (a renamed field, a score as a string, an entry with
 * no identifier) testable without depending on a remote API.
 *
 * **An unreadable payload returns an empty result, never an exception.** Enrichment is
 * optional: a scan that produced real results must not be marked failed because FIRST
 * changed the shape of its response.
 */

/** The EPSS API URL. Metadata only: nothing but CVE identifiers is sent there. */
export const EPSS_API_URL = 'https://api.first.org/data/v1/epss';

/** The catalog of actively exploited vulnerabilities, published by CISA. */
export const KEV_CATALOG_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

/**
 * The size of an EPSS query batch.
 *
 * Under the limit the API documents: too large a batch ends in a refusal which, here, would
 * be swallowed — hence in enrichment silently absent rather than a visible error.
 */
export const EPSS_BATCH_SIZE = 90;

/** A response's EPSS scores, indexed by CVE. */
export function parseEpssResponse(payload: unknown): Map<string, number> {
    const scores = new Map<string, number>();
    const data = (payload as { data?: unknown })?.data;
    if (!Array.isArray(data)) return scores;

    for (const entry of data) {
        const cve = (entry as { cve?: unknown })?.cve;
        const epss = (entry as { epss?: unknown })?.epss;
        if (typeof cve !== 'string' || cve === '') continue;

        // The API returns the score as a **string** ("0.00042"), not a number. Taking it as
        // is would store text in a numeric column, or yield `NaN`.
        //
        // The type filter comes before the conversion, and that is not decorative caution:
        // `Number(null)` and `Number('')` are **0**, which is a perfectly legitimate EPSS
        // score. Without this guard, an absent field would read as "zero probability of
        // exploitation" — absence disguised as good news.
        if (typeof epss !== 'number' && (typeof epss !== 'string' || epss.trim() === '')) continue;
        const value = Number(epss);
        if (!Number.isFinite(value)) continue;
        scores.set(cve, value);
    }
    return scores;
}

/** The KEV catalog's identifiers. */
export function parseKevCatalog(payload: unknown): Set<string> {
    const vulnerabilities = (payload as { vulnerabilities?: unknown })?.vulnerabilities;
    if (!Array.isArray(vulnerabilities)) return new Set();

    return new Set(
        vulnerabilities
            .map((entry) => (entry as { cveID?: unknown })?.cveID)
            .filter((id): id is string => typeof id === 'string' && id !== '')
    );
}

/** Splits a list of CVEs into queryable batches. */
export function batches<T>(items: T[], size: number = EPSS_BATCH_SIZE): T[][] {
    const result: T[][] = [];
    for (let index = 0; index < items.length; index += size) result.push(items.slice(index, index + size));
    return result;
}
