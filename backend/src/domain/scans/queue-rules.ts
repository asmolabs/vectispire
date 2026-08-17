/**
 * The scan queue's rules — pure, no queries.
 *
 * The queue lives in the database and not in a thread pool. Three reasons, each observed:
 * a pool makes the queue **invisible** (twelve scans triggered, no way to know which will
 * run when); **a restart loses it** (the rows survive, the futures do not, and those scans
 * stay pending forever); and the concurrency limit becomes a property of the process
 * instead of a setting.
 *
 * The order is creation order, with no priority. A priority column would be easy to add
 * and is deliberately missing: "in the order they were asked for" is a rule an operator
 * can predict, and the first thing a priority scheme costs is that predictability.
 */

/** A lease's duration. Past it, a scan is considered abandoned and becomes claimable again. */
export const LEASE_MS = Number(process.env.ZANSHIN_SCAN_LEASE_SECONDS ?? 1200) * 1000;

/**
 * How many takeovers before definitive failure.
 *
 * With no cap, a target that jams its worker every time would circulate from agent to
 * agent indefinitely, consuming the whole fleet's capacity — and the operator would see a
 * scan forever "about to start".
 */
export const MAX_ATTEMPTS = Number(process.env.ZANSHIN_SCAN_MAX_ATTEMPTS ?? 3);

/**
 * Claim attempts before giving up on a round.
 *
 * **Exists for MySQL**, which counts skipped rows against its `LIMIT`: with `LIMIT 1`, ten
 * concurrent claimants against a queue of twenty scans left six of them empty-handed.
 * Nothing was ever claimed twice — it was a throughput problem, whose production shape is
 * an agent polling for thirty seconds while work waits.
 *
 * PostgreSQL does not behave this way: it keeps scanning until it has `LIMIT` unlocked
 * rows. The loop exits as soon as the limit is reached or the queue is empty, so it costs
 * nothing where it is not needed.
 */
export const CLAIM_ATTEMPTS = Number(process.env.ZANSHIN_SCAN_CLAIM_ATTEMPTS ?? 12);

export const LEASE_EXHAUSTED_MESSAGE =
    'The scan was taken over too many times without completing: its worker stops responding before the end. ' +
    "Check the agent's logs, then run the scan again.";

/**
 * How many scans can still start.
 *
 * Computed on every dispatch rather than fixed at startup: that is what makes the limit
 * changeable without restarting the application.
 */
export function capacity(maxConcurrent: number, running: number): number {
    return Math.max(0, maxConcurrent - running);
}

/** A lease that never expires is not a lease: an absent date counts as expired. */
export function leaseHasLapsed(leaseExpiresAt: Date | null, asOf: Date): boolean {
    return leaseExpiresAt === null || leaseExpiresAt < asOf;
}

/**
 * What becomes of a scan whose lease has lapsed.
 *
 * Nothing is *stopped* here: the work may still be running elsewhere, and nothing in this
 * process can kill a thread on another machine. The row becomes claimable again, and it is
 * `stillOwned` that will later refuse the deposed worker's results.
 */
export function afterLapse(attempts: number): 'requeue' | 'fail' {
    return attempts >= MAX_ATTEMPTS ? 'fail' : 'requeue';
}

/** The lease to set at the moment of a claim. */
export function leaseUntil(claimedAt: Date): Date {
    return new Date(claimedAt.getTime() + LEASE_MS);
}
