import { createHash } from 'node:crypto';
import { canonical } from '../common/timestamp';

/**
 * The audit log's integrity chain.
 *
 * Each entry carries the previous one's hash. Modifying or deleting a past row breaks
 * every hash that follows. This does not make the log immutable — whoever can write to
 * the table can rewrite the whole chain — but it makes *selective* modification
 * detectable, which is the realistic threat when the interesting row is one among
 * thousands.
 *
 * ## The timestamp goes in canonically
 *
 * `canonical()`, that is ISO 8601 UTC to the millisecond. A security control must not
 * depend on how an engine renders its dates: `.123000` and `.123` denote the same instant
 * and would give two hashes. Two processes in two timezones therefore produce the same
 * string for the same instant.
 *
 * The field separator is the NUL byte, which cannot appear in any of the hashed values —
 * without which two different entries could produce the same concatenation.
 */

/** The fields of an entry that go into its hash, in this order. */
export interface AuditEntryForHash {
    previousHash: string | null;
    /** The instant as the database returns it. Canonicalized here, not by the caller. */
    timestamp: Date | null;
    operationType: string | null;
    resourceId: string | null;
    userId: string | null;
    ipAddress: string | null;
    userAgent: string | null;
    description: string | null;
}

/**
 * `H(previous | timestamp | operation | resource | user | ip | user_agent | description)`.
 *
 * The field order is fixed, and the separator is a **NUL** byte: no content can then
 * imitate a field boundary. Without that, a description ending in the right characters
 * could shift the meaning of the next field.
 *
 * `null` and the empty string are indistinguishable here, deliberately: both mean "this
 * field has no value", and telling them apart would make the hash depend on how a driver
 * renders an empty column.
 */
export function computeEntryHash(entry: AuditEntryForHash): string {
    const parts = [
        entry.previousHash ?? '',
        entry.timestamp ? canonical(entry.timestamp) : '',
        entry.operationType ?? '',
        entry.resourceId ?? '',
        entry.userId ?? '',
        entry.ipAddress ?? '',
        entry.userAgent ?? '',
        entry.description ?? ''
    ];
    return createHash('sha256').update(parts.join('\0'), 'utf8').digest('hex');
}

/** An entry as it is read back for verification. */
export interface AuditEntryForVerification extends AuditEntryForHash {
    id: string;
    entryHash: string | null;
}

/**
 * `null` if the log is intact, otherwise a description of the first break.
 *
 * ## A graph, not a queue
 *
 * Verification used to require a strictly unique chain: each entry had to point at the one
 * preceding it in the list. **Two web instances writing at the same instant read the same
 * tail** and produce two entries carrying the same predecessor; the chain forks, and a
 * perfectly honest log declared itself broken. A false alarm in an integrity check is worse
 * than useless — you learn to ignore it, and it then covers the real ones.
 *
 * What is checked here therefore no longer depends on order:
 *
 * 1. **Each entry matches its own hash** — this is what detects a row being modified, the
 *    realistic threat when the interesting row is one among thousands.
 * 2. **Each entry's predecessor still exists** — this is what detects the deletion of an
 *    entry somebody descends from.
 * 3. **No entry without a hash is later than the start of the chaining** — this is what
 *    detects a row placed by hand. Entries predating the chaining are counted rather than
 *    reported: "these rows are not verifiable" is information, not an absence of it.
 *
 * ## What this no longer detects, and it has to be said
 *
 * **The deletion of an entry nobody descends from** — the last one written, or the tip of a
 * branch. Nothing points at it, so nothing is missing once it is gone. That is the price
 * paid for no longer crying wolf, and it is accepted: closing that case would mean
 * serializing every audit write, which would make each audited action wait behind the
 * others for as long as their transaction lasts.
 *
 * The order of the entries no longer matters to this function.
 */
export function verifyChain(entries: AuditEntryForVerification[]): {
    broken: string | null;
    unverifiable: number;
} {
    const chained = entries.filter((entry) => entry.entryHash);
    const unverifiable = entries.length - chained.length;

    // Every hash present, so we know what it is legitimate to point at.
    const known = new Set(chained.map((entry) => entry.entryHash as string));

    // **An entry without a hash is only legitimate if it does not follow the chaining.**
    // That is the case for rows written before the chain existed. The marker is the
    // timestamp and not the position in the list: the latter means nothing any more now
    // that concurrent branches are admitted.
    //
    // Strictly later, and not "from onwards": an inherited row written in the same
    // millisecond as the first chained entry — the instant of the switchover — must not
    // raise an alarm. What that concedes is thin: a forged entry would have to carry a date
    // earlier than the whole chained log, hence pass itself off as a pre-switchover row,
    // which stops it from imitating a recent action.
    const oldestChained = chained.reduce<number | null>(
        (oldest, entry) => (entry.timestamp && (oldest === null || entry.timestamp.getTime() < oldest) ? entry.timestamp.getTime() : oldest),
        null
    );
    for (const entry of entries) {
        if (entry.entryHash || oldestChained === null) continue;
        if (entry.timestamp && entry.timestamp.getTime() > oldestChained) {
            return {
                broken: `Entry ${entry.id} has no hash although the chaining had started: the row was inserted or modified.`,
                unverifiable
            };
        }
    }

    for (const entry of chained) {
        if (entry.entryHash !== computeEntryHash(entry)) {
            return {
                broken: `Entry ${entry.id}: its own content no longer matches its hash.`,
                unverifiable
            };
        }
        // `null` is legitimate: it is a root. There is one per branch, and one branch per
        // instance that wrote at the same time as another.
        if (entry.previousHash !== null && !known.has(entry.previousHash)) {
            return {
                broken: `Entry ${entry.id}: its predecessor ${JSON.stringify(entry.previousHash)} has vanished from the log — an earlier entry was deleted.`,
                unverifiable
            };
        }
    }

    return { broken: null, unverifiable };
}

/**
 * Recomputes the whole chain, oldest to newest.
 *
 * This is the switchover operation: entries written by the Python implementation carry
 * hashes computed on the old formula and no longer verify.
 *
 * **An operation to run once, with somebody watching.** Rewriting an integrity log is
 * precisely what that log exists to make detectable: it must never be triggered
 * automatically, not at startup, not by a route.
 *
 * Does not modify entry content — only `previousHash` and `entryHash`.
 */
export function rebuildChain<T extends AuditEntryForVerification>(entries: T[]): T[] {
    let previousHash: string | null = null;
    for (const entry of entries) {
        entry.previousHash = previousHash;
        entry.entryHash = computeEntryHash(entry);
        previousHash = entry.entryHash;
    }
    return entries;
}
