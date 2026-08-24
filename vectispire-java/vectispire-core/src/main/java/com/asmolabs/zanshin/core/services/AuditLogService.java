package com.asmolabs.zanshin.core.services;

import com.asmolabs.zanshin.common.domain.audit.AuditChain;
import com.asmolabs.zanshin.common.domain.audit.AuditOperation;
import com.asmolabs.zanshin.core.persistence.AuditLogEntity;
import com.asmolabs.zanshin.core.repositories.AuditLog;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Writing and verifying the audit log.
 *
 * <p><b>{@link #record} never throws.</b> A failure to write the log must not fail the action
 * it describes: the opposite would give a full table the power to stop an administrator
 * logging in.
 */
@Service
public class AuditLogService {

    private static final Logger log = LoggerFactory.getLogger(AuditLogService.class);

    /** The column's width. Truncated here so an over-long description costs its tail, not the entry. */
    private static final int DESCRIPTION_MAX_LENGTH = 255;

    private final AuditLog entries;
    private final AuditMirror mirror;
    private final Clock clock;

    /**
     * The last instant handed out, so that instants strictly increase.
     *
     * <p>A clock's resolution is finite: two entries written in the same millisecond would carry
     * the same timestamp, and the order between them would then be decided by a random UUID. The
     * chain would be built in one order and read back in another, and verification would fail on
     * a perfectly intact log — which a test showed on five entries written in a tight loop.
     *
     * <p>Advancing by a millisecond rather than waiting: the log does not need an exact clock, it
     * needs an order. The drift is bounded by the write rate and disappears at the first pause.
     *
     * <p>Per instance, and that is a known limit: two instances writing in the same millisecond
     * legitimately fork, and verification breaks the tie on the identifier. See {@code
     * AuditLog#findAllByOrderByTimestampAscIdAsc}.
     */
    private final AtomicLong lastIssued = new AtomicLong(Long.MIN_VALUE);

    public AuditLogService(AuditLog entries, AuditMirror mirror, Clock clock) {
        this.entries = entries;
        this.mirror = mirror;
        this.clock = clock;
    }

    /**
     * @param userId the username, not the numeric identifier: an entry must stay readable after
     *     the account is deleted
     */
    public record Record(
            AuditOperation operation,
            String resourceId,
            String description,
            String userId,
            String ipAddress,
            String userAgent) {

        public static Record of(AuditOperation operation, String resourceId, String description, String userId) {
            return new Record(operation, resourceId, description, userId, null, null);
        }
    }

    /**
     * Appends an entry.
     *
     * <p><b>In its own transaction.</b> The audited action's transaction may still roll back —
     * a triage that violates a constraint, a scan trigger that fails validation — and the
     * attempt is exactly what an auditor wants to see. Joining the caller's transaction would
     * erase the record of everything that did not succeed.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void record(Record entry) {
        try {
            String previousHash = entries.findTopByOrderByTimestampDescIdDesc()
                    .map(AuditLogEntity::getEntryHash)
                    .orElse(null);

            AuditLogEntity row = new AuditLogEntity();
            // Set here rather than left to a column default: the hash covers the timestamp, and
            // a value applied by the database after the computation would make every entry fail
            // its own verification.
            row.setTimestamp(monotonicNow());
            row.setOperationType(entry.operation().wireName());
            row.setResourceId(String.valueOf(entry.resourceId()));
            row.setDescription(truncate(entry.description()));
            row.setUserId(entry.userId());
            row.setIpAddress(blankToNull(entry.ipAddress()));
            row.setUserAgent(truncate(blankToNull(entry.userAgent())));
            row.setPreviousHash(previousHash);
            row.setEntryHash(AuditChain.computeEntryHash(chainEntry(row)));

            entries.save(row);

            // **Mirrored before this transaction commits, deliberately.** A rollback after the
            // line is written leaves the mirror holding an entry the table never kept, which
            // `verifyAgainstMirror` reports as unrecorded — noise. Writing after the commit
            // instead would leave the opposite: an action that rolled the transaction back could
            // keep an entry out of the mirror entirely, which is the case the mirror exists for.
            // Noise that can be explained beats a hole that cannot.
            if (!mirror.append(mirrored(row))) {
                log.error("Audit entry {} is in the table but not in the mirror", row.getId());
            }
        } catch (RuntimeException failed) {
            // See the class note: never at the expense of the action being described. Logged at
            // error level, because a log that stops recording in silence is worse than one that
            // stops loudly.
            log.error("Audit entry could not be written: {}", failed.getMessage(), failed);
        }
    }

    @Transactional(readOnly = true)
    public List<AuditLogEntity> recent(int limit) {
        return entries.findRecent(org.springframework.data.domain.Limit.of(limit));
    }

    /**
     * Empty {@code broken} when the chain is intact, otherwise the first break.
     *
     * <p>Reads the whole table: a deliberate verification, not something done on every page
     * render.
     */
    @Transactional(readOnly = true)
    public AuditChain.Verification verify() {
        return AuditChain.verifyChain(entries.findAllByOrderByTimestampAscIdAsc().stream()
                .map(AuditLogService::verifiable)
                .toList());
    }

    /**
     * What the table and the mirror say about each other.
     *
     * @param configured false when no mirror is set up — reported rather than hidden, because
     *     "0 missing" from a mirror that does not exist reads as reassurance and is not
     * @param missingFromTable entries the mirror holds and the table does not: <b>the case the
     *     chain cannot see</b>. Deleting the last entry, or the tip of a branch, leaves a chain
     *     that verifies perfectly — nobody descends from what was removed. Here it is one
     *     subtraction
     * @param missingFromMirror entries the table holds and the mirror does not: written before
     *     the mirror was configured, written while its disk was full, or inserted by somebody
     *     who had the database and not the file. The three are not distinguishable from here,
     *     and saying so is the honest report
     */
    public record MirrorComparison(boolean configured, int missingFromTable, int missingFromMirror) {}

    /**
     * Compares the two copies.
     *
     * <p>By entry hash, which is what makes the comparison cheap and exact: the hash covers
     * every field the entry is made of, so two copies of one entry agree on it and two different
     * entries cannot.
     *
     * <p>Multiset semantics, not set: the same entry appearing twice in the mirror and once in
     * the table is a difference worth one, not zero. A duplicate line is how a retried write
     * shows up, and it should not hide a deletion.
     */
    @Transactional(readOnly = true)
    public MirrorComparison verifyAgainstMirror() {
        if (!mirror.configured()) {
            return new MirrorComparison(false, 0, 0);
        }

        java.util.Map<String, Integer> inMirror = new java.util.HashMap<>();
        for (String hash : mirror.entryHashes()) {
            inMirror.merge(hash, 1, Integer::sum);
        }

        int missingFromMirror = 0;
        for (AuditLogEntity row : entries.findAllByOrderByTimestampAscIdAsc()) {
            String hash = row.getEntryHash();
            if (hash == null || hash.isBlank()) {
                // Predates the chaining: it has no hash to compare, and counting it as missing
                // would report an alarm about entries nobody ever claimed were covered.
                continue;
            }
            Integer remaining = inMirror.get(hash);
            if (remaining == null || remaining == 0) {
                missingFromMirror++;
            } else {
                inMirror.put(hash, remaining - 1);
            }
        }

        int missingFromTable = inMirror.values().stream().mapToInt(Integer::intValue).sum();
        return new MirrorComparison(true, missingFromTable, missingFromMirror);
    }

    /**
     * Recomputes the whole chain. <b>A migration operation, and nothing else.</b>
     *
     * <p>To be run with somebody watching: rewriting an integrity log is exactly what that log
     * exists to make detectable. It is therefore wired to no route and to no startup — it is an
     * operations command.
     */
    @Transactional
    public int rebuild() {
        List<AuditChain.VerifiableEntry> rebuilt = AuditChain.rebuildChain(
                entries.findAllByOrderByTimestampAscIdAsc().stream()
                        .map(AuditLogService::verifiable)
                        .toList());
        for (AuditChain.VerifiableEntry entry : rebuilt) {
            entries.updateHashes(UUID.fromString(entry.id()), entry.entry().previousHash(), entry.entryHash());
        }
        return rebuilt.size();
    }

    private Instant monotonicNow() {
        long candidate = clock.instant().toEpochMilli();
        long issued = lastIssued.updateAndGet(previous -> candidate > previous ? candidate : previous + 1);
        return Instant.ofEpochMilli(issued);
    }

    private static AuditChain.Entry chainEntry(AuditLogEntity row) {
        return new AuditChain.Entry(
                row.getPreviousHash(),
                row.getTimestamp(),
                row.getOperationType(),
                row.getResourceId(),
                row.getUserId(),
                row.getIpAddress(),
                row.getUserAgent(),
                row.getDescription());
    }

    private static AuditMirror.Entry mirrored(AuditLogEntity row) {
        return new AuditMirror.Entry(
                String.valueOf(row.getId()),
                // The canonical form the hash itself uses, so the mirror and the table cannot
                // disagree about an instant merely because one of them printed it differently.
                com.asmolabs.zanshin.common.domain.crypto.Digests.canonical(row.getTimestamp()),
                row.getOperationType(),
                row.getResourceId(),
                row.getUserId(),
                row.getIpAddress(),
                row.getUserAgent(),
                row.getDescription(),
                row.getPreviousHash(),
                row.getEntryHash());
    }

    private static AuditChain.VerifiableEntry verifiable(AuditLogEntity row) {
        return new AuditChain.VerifiableEntry(row.getId().toString(), row.getEntryHash(), chainEntry(row));
    }

    private static String truncate(String value) {
        if (value == null) {
            return null;
        }
        return value.length() <= DESCRIPTION_MAX_LENGTH ? value : value.substring(0, DESCRIPTION_MAX_LENGTH);
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value;
    }
}
