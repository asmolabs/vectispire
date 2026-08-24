package com.asmolabs.vectispire.common.domain.audit;

import com.asmolabs.vectispire.common.domain.crypto.Digests;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * The audit log's integrity chain.
 *
 * <p>Each entry carries the previous one's hash. Modifying or deleting a past row breaks
 * every hash that follows. This does not make the log immutable — whoever can write to the
 * table can rewrite the whole chain — but it makes <em>selective</em> modification
 * detectable, which is the realistic threat when the interesting row is one among thousands.
 *
 * <h2>The timestamp goes in canonically</h2>
 *
 * <p>{@link Digests#canonical} — ISO 8601 UTC to the millisecond. A security control must
 * not depend on how an engine renders its dates: {@code .123000} and {@code .123} denote the
 * same instant and would give two hashes.
 *
 * <p>The field separator is the NUL byte, which cannot appear in any hashed value; without it
 * two different entries could produce the same concatenation.
 */
public final class AuditChain {

    private AuditChain() {}

    /** The fields of an entry that go into its hash, in this order. */
    public record Entry(
            String previousHash,
            /* The instant as the database returns it. Canonicalized here, not by the caller. */
            Instant timestamp,
            String operationType,
            String resourceId,
            String userId,
            String ipAddress,
            String userAgent,
            String description) {}

    /** An entry as it is read back for verification. */
    public record VerifiableEntry(String id, String entryHash, Entry entry) {}

    /**
     * @param broken {@code null} if the log is intact, otherwise a description of the first break
     * @param unverifiable how many entries predate the chaining
     */
    public record Verification(String broken, int unverifiable) {}

    /**
     * {@code H(previous | timestamp | operation | resource | user | ip | user_agent |
     * description)}.
     *
     * <p>The field order is fixed and the separator is a <b>NUL</b> byte, so no content can
     * imitate a field boundary. Without it, a description ending in the right characters could
     * shift the meaning of the next field.
     *
     * <p>{@code null} and the empty string are indistinguishable here, deliberately: both mean
     * "this field has no value", and telling them apart would make the hash depend on how a
     * driver renders an empty column.
     */
    public static String computeEntryHash(Entry entry) {
        return Digests.sha256Fields(
                entry.previousHash(),
                entry.timestamp() == null ? null : Digests.canonical(entry.timestamp()),
                entry.operationType(),
                entry.resourceId(),
                entry.userId(),
                entry.ipAddress(),
                entry.userAgent(),
                entry.description());
    }

    /**
     * Verifies the log.
     *
     * <h2>A graph, not a queue</h2>
     *
     * <p>Verification used to require a strictly unique chain: each entry had to point at the
     * one preceding it in the list. <b>Two instances writing at the same instant read the same
     * tail</b> and produce two entries carrying the same predecessor; the chain forks, and a
     * perfectly honest log declared itself broken. A false alarm in an integrity check is worse
     * than useless — you learn to ignore it, and it then covers the real ones.
     *
     * <p>What is checked therefore no longer depends on order:
     *
     * <ol>
     *   <li><b>Each entry matches its own hash</b> — detects a row being modified, the realistic
     *       threat when the interesting row is one among thousands.
     *   <li><b>Each entry's predecessor still exists</b> — detects the deletion of an entry
     *       somebody descends from.
     *   <li><b>No entry without a hash is later than the start of the chaining</b> — detects a
     *       row placed by hand. Entries predating the chaining are counted rather than
     *       reported: "these rows are not verifiable" is information, not an absence of it.
     * </ol>
     *
     * <h2>What this no longer detects, and it has to be said</h2>
     *
     * <p><b>The deletion of an entry nobody descends from</b> — the last one written, or the tip
     * of a branch. Nothing points at it, so nothing is missing once it is gone. That is the
     * price paid for no longer crying wolf, and it is accepted: closing the case would mean
     * serializing every audit write, making each audited action wait behind the others for as
     * long as their transaction lasts.
     */
    public static Verification verifyChain(List<VerifiableEntry> entries) {
        List<VerifiableEntry> chained = entries.stream()
                .filter(e -> e.entryHash() != null && !e.entryHash().isEmpty())
                .toList();
        int unverifiable = entries.size() - chained.size();

        // Every hash present, so we know what it is legitimate to point at.
        Set<String> known = new HashSet<>();
        for (VerifiableEntry entry : chained) {
            known.add(entry.entryHash());
        }

        // **An entry without a hash is only legitimate if it does not follow the chaining.**
        // That is the case for rows written before the chain existed. The marker is the
        // timestamp, not the position in the list: the latter stopped meaning anything once
        // concurrent branches were admitted.
        //
        // Strictly later, not "from onwards": an inherited row written in the same millisecond
        // as the first chained entry — the instant of the switchover — must not raise an alarm.
        // What that concedes is thin: a forged entry would have to carry a date earlier than
        // the whole chained log, hence pass itself off as a pre-switchover row, which stops it
        // from imitating a recent action.
        Instant oldestChained = null;
        for (VerifiableEntry entry : chained) {
            Instant at = entry.entry().timestamp();
            if (at != null && (oldestChained == null || at.isBefore(oldestChained))) {
                oldestChained = at;
            }
        }

        if (oldestChained != null) {
            for (VerifiableEntry entry : entries) {
                if (entry.entryHash() != null && !entry.entryHash().isEmpty()) {
                    continue;
                }
                Instant at = entry.entry().timestamp();
                if (at != null && at.isAfter(oldestChained)) {
                    return new Verification(
                            "Entry " + entry.id()
                                    + " has no hash although the chaining had started: the row was inserted or modified.",
                            unverifiable);
                }
            }
        }

        for (VerifiableEntry entry : chained) {
            if (!entry.entryHash().equals(computeEntryHash(entry.entry()))) {
                return new Verification(
                        "Entry " + entry.id() + ": its own content no longer matches its hash.", unverifiable);
            }
            // `null` is legitimate: it is a root. There is one per branch, and one branch per
            // instance that wrote at the same time as another.
            String previous = entry.entry().previousHash();
            if (previous != null && !known.contains(previous)) {
                return new Verification(
                        "Entry " + entry.id() + ": its predecessor \"" + previous
                                + "\" has vanished from the log — an earlier entry was deleted.",
                        unverifiable);
            }
        }

        return new Verification(null, unverifiable);
    }

    /**
     * Recomputes the whole chain, oldest to newest.
     *
     * <p>This is the switchover operation: entries written by an earlier implementation carry
     * hashes computed on the old formula and no longer verify.
     *
     * <p><b>An operation to run once, with somebody watching.</b> Rewriting an integrity log is
     * precisely what that log exists to make detectable: it must never be triggered
     * automatically, not at startup, not by a route.
     *
     * <p>Returns new entries rather than mutating the given ones — the original had no choice,
     * this port does. Content is untouched; only {@code previousHash} and {@code entryHash}
     * change.
     */
    public static List<VerifiableEntry> rebuildChain(List<VerifiableEntry> entries) {
        List<VerifiableEntry> rebuilt = new ArrayList<>(entries.size());
        String previousHash = null;
        for (VerifiableEntry entry : entries) {
            Entry source = entry.entry();
            Entry relinked = new Entry(
                    previousHash,
                    source.timestamp(),
                    source.operationType(),
                    source.resourceId(),
                    source.userId(),
                    source.ipAddress(),
                    source.userAgent(),
                    source.description());
            String hash = computeEntryHash(relinked);
            rebuilt.add(new VerifiableEntry(entry.id(), hash, relinked));
            previousHash = hash;
        }
        return rebuilt;
    }
}
