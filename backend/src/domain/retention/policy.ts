/**
 * The retention policy for raw scanner payloads.
 *
 * `Scan.sbom` and `Scan.cves` carry the tools' untouched output. A container scan of a JRE
 * image weighs around 2.5 MB of SBOM, and nothing ever deleted anything: the database
 * grows indefinitely for as long as the scheduler runs.
 *
 * **What is purged and what is kept is the whole subject.**
 *
 * - *Purged*: `sbom` and `cves`, the raw blobs. They exist for audit — "what exactly did
 *   Syft report that day" — and that value decays quickly.
 * - *Kept, always*: `summary` and `findingsCount` (the numbers the history displays),
 *   every finding, every issue. **The normalized projection *is* the durable record** —
 *   which is what it was built for — so purging a blob costs no history, no triage, no
 *   delta.
 *
 * The two rules combine, they do not add up: a scan is purgeable only if it is **both**
 * outside the "last N of this target" window **and** older than the age limit. Requiring
 * both means a target scanned twice a year keeps its payloads, and a target scanned every
 * hour stays bounded — neither rule alone achieves that.
 */

export const SETTING_RETENTION_KEEP_PER_TARGET = 'retention_keep_per_target';
export const SETTING_RETENTION_MAX_AGE_DAYS = 'retention_max_age_days';

/**
 * Keep the raw output of each target's last ten scans, and of anything less than ninety
 * days old. Generous defaults: the goal is to bound growth, not to be stingy, and an
 * operator investigating a regression looks at recent scans.
 */
export const DEFAULT_KEEP_PER_TARGET = 10;
export const DEFAULT_MAX_AGE_DAYS = 90;

/** Zero on one axis means "no limit on that axis"; zero on both disables purging. */
export const UNLIMITED = 0;

export interface RetentionPolicy {
    keepPerTarget: number;
    maxAgeDays: number;
}

/** A disabled policy purges nothing at all. */
export function isEnabled(policy: RetentionPolicy): boolean {
    return policy.keepPerTarget !== UNLIMITED || policy.maxAgeDays !== UNLIMITED;
}

/**
 * An integer setting, or its default.
 *
 * An unreadable value falls back to the default rather than to zero: zero means "no
 * limit", so a typo in the settings would silently disable retention and the database
 * would start growing again with nothing saying so.
 */
export function intSetting(raw: string, fallback: number): number {
    // The empty string is discarded before the conversion, and that is the point:
    // `Number('')` is **0**, which here means "no limit". An absent setting would
    // therefore disable retention instead of applying its default, and the database would
    // start growing again with nothing saying so.
    if (raw.trim() === '') return fallback;

    const value = Number(raw);
    if (!Number.isInteger(value) || value < 0) return fallback;
    return value;
}

/** The date before which a scan is old enough to be purged, or `null` if unlimited. */
export function cutoffDate(policy: RetentionPolicy, now: Date): Date | null {
    if (policy.maxAgeDays === UNLIMITED) return null;
    return new Date(now.getTime() - policy.maxAgeDays * 86_400_000);
}

/** A candidate scan, reduced to what the decision needs. */
export interface Candidate {
    id: number;
    repoId: number | null;
    containerId: number | null;
    createdAt: Date;
}

/**
 * The scans whose raw payloads can be dropped.
 *
 * Candidates must arrive **newest to oldest**, target by target: that order is what gives
 * the rank its meaning, and a different sort would purge the most recent scans —
 * precisely the ones the payloads exist for.
 */
export function prunable(candidates: Candidate[], policy: RetentionPolicy, now: Date): number[] {
    if (!isEnabled(policy)) return [];

    const cutoff = cutoffDate(policy, now);
    const rankPerTarget = new Map<string, number>();
    const ids: number[] = [];

    for (const candidate of candidates) {
        const target = candidate.repoId !== null ? `repo:${candidate.repoId}` : `container:${candidate.containerId}`;
        const rank = rankPerTarget.get(target) ?? 0;
        rankPerTarget.set(target, rank + 1);

        if (policy.keepPerTarget !== UNLIMITED && rank < policy.keepPerTarget) continue;
        if (cutoff !== null && candidate.createdAt >= cutoff) continue;
        ids.push(candidate.id);
    }
    return ids;
}
