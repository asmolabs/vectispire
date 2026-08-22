package com.asmolabs.zanshin.core.services;

import java.util.List;

/**
 * A second copy of the audit log, outside the database the audit log watches.
 *
 * <p><b>The limit this exists for.</b> The chain makes <em>selective</em> editing detectable:
 * change one row among thousands and its hash stops matching. It does not make the log immutable
 * — whoever can write the table can recompute every hash from the edited row onward, and the
 * chain then verifies perfectly. Two cases stay open with the table alone, and they are the
 * realistic ones: rewriting the whole chain, and deleting an entry nobody descends from (the
 * last one written, which is exactly the entry an attacker wants gone).
 *
 * <p>A mirror closes both, and it is worth being precise about how. It does not make the copy
 * unforgeable: a file on the same host can be edited too. What it does is force the edit to be
 * made <b>twice, in two media, with two sets of permissions</b> — and the mirror is normally
 * shipped off the host by a log collector within seconds, at which point the second copy is
 * beyond reach of whoever holds the database.
 *
 * <p><b>Off unless configured, and said out loud.</b> Writing to a path by default fails on a
 * read-only container filesystem, and an integrity control that logs a warning on every start is
 * one people learn to ignore. So the default is {@link Disabled} — and
 * {@code /audit-log/verify} reports that no mirror is configured, so the gap is visible in the
 * product rather than only in a document.
 */
public interface AuditMirror {

    /** One entry, in the form the mirror stores and compares. */
    record Entry(
            String id,
            String timestamp,
            String operation,
            String resourceId,
            String userId,
            String ipAddress,
            String userAgent,
            String description,
            String previousHash,
            String entryHash) {}

    /**
     * Appends an entry. <b>Must not throw</b>: the caller is recording something that already
     * happened, and a failure here must not fail the audited action any more than a failure to
     * write the row does.
     *
     * @return false when the entry could not be written, so the caller can log it. The
     *     verification will see it too — an entry in the table and not in the mirror is exactly
     *     the difference this reports
     */
    boolean append(Entry entry);

    /** Whether a mirror is configured at all, for the verification to report honestly. */
    boolean configured();

    /**
     * Every entry hash the mirror holds, in the order written.
     *
     * <p>Hashes rather than whole entries: comparing sets of hashes answers both questions worth
     * asking — what the table lost, and what the mirror never saw — and reading the descriptions
     * back would mean holding the whole log in memory to compare fields that the hash already
     * covers.
     */
    List<String> entryHashes();

    /** The mirror that is not there. */
    final class Disabled implements AuditMirror {

        @Override
        public boolean append(Entry entry) {
            // True, not false: nothing failed. A disabled mirror reporting failure on every
            // entry would fill the log with an alarm about a feature nobody turned on.
            return true;
        }

        @Override
        public boolean configured() {
            return false;
        }

        @Override
        public List<String> entryHashes() {
            return List.of();
        }
    }
}
