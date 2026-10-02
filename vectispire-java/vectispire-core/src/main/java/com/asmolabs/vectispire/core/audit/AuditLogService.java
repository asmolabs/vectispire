package com.asmolabs.vectispire.core.audit;

import com.asmolabs.vectispire.common.domain.audit.AuditChain;
import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.siem.SecurityEventType;
import com.asmolabs.vectispire.core.audit.internal.AuditMirror;
import com.asmolabs.vectispire.core.audit.persistence.AuditChainHeadEntity;
import com.asmolabs.vectispire.core.audit.persistence.AuditChainHeadRepository;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogEntity;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogRepository;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.PessimisticLockingFailureException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionOperations;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;

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

    /**
     * The widths of the bounded columns ({@code t_audit_log}). Every value is cut to its column
     * here, so an over-long one costs its tail and not the entry.
     *
     * <p>Not only the description. A resource id built from a request — the joined keys of a
     * settings write, the URI of a refused request — or a user agent or address from a header has
     * no length the caller controls, and MySQL and PostgreSQL refuse the whole row.
     */
    private static final int TEXT_COLUMN = 255;

    private static final int ADDRESS_COLUMN = 64;

    private final AuditLogRepository entries;
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
     * AuditLogRepository#findAllByOrderByTimestampAscIdAsc}.
     */
    private final AtomicLong lastIssued = new AtomicLong(Long.MIN_VALUE);

    /** Told of every entry once it is committed — the SIEM export's hook. See {@link Listener}. */
    private final List<Listener> listeners;

    /** The entry's own transaction — see {@link #record}. */
    private final TransactionOperations separately;

    /**
     * Taken first in every entry's transaction, and held until it ends (V66).
     *
     * <p><b>The chain forked under concurrent writers.</b> An entry read the newest entry and inserted
     * itself onto it, and the read took no lock: two writers that read the same head before either
     * committed both chained onto it, and the verification reported a break in a log nobody touched —
     * eight threads of one instance did it on MySQL and PostgreSQL, and so did two instances
     * ({@code AuditChainConcurrencyIntegrationTest}). The lock is a row of the database's, so it
     * serialises the writers of every instance; the cost is that entries are written one at a time,
     * each in a transaction a few statements long.
     */
    private final Runnable lockChain;

    @Autowired
    public AuditLogService(
            AuditLogRepository entries,
            AuditChainHeadRepository heads,
            AuditMirror mirror,
            Clock clock,
            List<Listener> listeners,
            PlatformTransactionManager transactions) {
        this(entries, mirror, clock, listeners, requiresNew(transactions), () -> heads.lock(AuditChainHeadEntity.THE_ROW)
                .orElseThrow(() -> new IllegalStateException(
                        "t_audit_chain_head has lost its row: audit entries are not written without the chain's lock")));
    }

    /**
     * With the boundary supplied — {@link TransactionOperations#withoutTransaction()} for a unit
     * test that has no database, and therefore no chain to lock and no second writer to wait for.
     */
    public AuditLogService(
            AuditLogRepository entries,
            AuditMirror mirror,
            Clock clock,
            List<Listener> listeners,
            TransactionOperations separately) {
        this(entries, mirror, clock, listeners, separately, () -> {});
    }

    private AuditLogService(
            AuditLogRepository entries,
            AuditMirror mirror,
            Clock clock,
            List<Listener> listeners,
            TransactionOperations separately,
            Runnable lockChain) {
        this.entries = entries;
        this.mirror = mirror;
        this.clock = clock;
        this.listeners = List.copyOf(listeners);
        this.separately = separately;
        this.lockChain = lockChain;
    }

    private static TransactionTemplate requiresNew(PlatformTransactionManager transactions) {
        TransactionTemplate template = new TransactionTemplate(transactions);
        template.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        return template;
    }

    /**
     * Something that acts on an entry once it exists.
     *
     * <p><b>In the entry's transaction first, after its commit only if that failed</b> (decision
     * 0033). A listener acted only after the commit, which made a failing listener harmless and a
     * stop between the commit and the listener's own transaction a lost effect: every SIEM event an
     * entry signals left that way, with nothing to send it again. {@link #recordedInTransaction}
     * writes in the entry's transaction, so the entry and what it causes commit together.
     *
     * <p><b>A listener that fails still cannot cost the entry.</b> A failure there aborts the
     * transaction — an exception leaving a participating proxy marks it rollback-only anyway — and
     * the entry is written again on its own, with {@link #recorded} called after that commit: the
     * old path, kept as the fallback rather than the rule. The two are never both called for one
     * entry.
     */
    public interface Listener {

        /** Inside the entry's transaction. Writes only in it; anything it throws aborts that transaction. */
        void recordedInTransaction(Record entry, Instant at);

        /** After the entry's commit, when {@link #recordedInTransaction} could not be. Exceptions are logged here. */
        void recorded(Record entry, Instant at);
    }

    /**
     * @param userId the username, not the numeric identifier: an entry must stay readable after
     *     the account is deleted
     * @param signal the security event this entry stands for, when its writer says so; {@code null}
     *     leaves it to {@link SecurityEventType#signalledBy}, which answers only for operations that
     *     are unambiguous. Not stored — the column set, and so the hash chain, is unchanged
     */
    public record Record(
            AuditOperation operation,
            String resourceId,
            String description,
            String userId,
            String ipAddress,
            String userAgent,
            SecurityEventType signal) {

        public Record(
                AuditOperation operation,
                String resourceId,
                String description,
                String userId,
                String ipAddress,
                String userAgent) {
            this(operation, resourceId, description, userId, ipAddress, userAgent, null);
        }

        public static Record of(AuditOperation operation, String resourceId, String description, String userId) {
            return new Record(operation, resourceId, description, userId, null, null);
        }

        /**
         * The same entry, naming the security event it stands for.
         *
         * <p>For the operations too broad to signal on their own — a {@code LOGIN_BLOCKED} is the
         * throttle and also "password sign-in is off"; a {@code SETTING_UPDATED} is the four-eyes
         * switch and also a branch name. The writer knows which it is; the operation does not.
         */
        public Record signalling(SecurityEventType event) {
            return new Record(operation, resourceId, description, userId, ipAddress, userAgent, event);
        }
    }

    /**
     * Appends an entry.
     *
     * <p><b>In its own transaction.</b> The audited action's transaction may still roll back —
     * a triage that violates a constraint, a scan trigger that fails validation — and the
     * attempt is exactly what an auditor wants to see. Joining the caller's transaction would
     * erase the record of everything that did not succeed.
     *
     * <p><b>A {@link TransactionTemplate}, not the annotation, and the row flushed inside the
     * {@code try}.</b> The identifier is generated by Hibernate, so a plain {@code save} issued no
     * statement: the INSERT ran at the commit, after this method's {@code catch} — a row the
     * database refused made {@code record} throw into the audited action, with the mirror line
     * already written and no row kept. Flushing moves the refusal inside the {@code try}, before the
     * mirror; the template moves the commit itself inside it, where the annotation's commit ran in
     * the proxy, out of reach of any {@code catch} here.
     */
    public void record(Record entry) {
        try {
            writeWithItsEffects(entry);
        } catch (RuntimeException failed) {
            // See the class note: never at the expense of the action being described. Logged at
            // error level, because a log that stops recording in silence is worse than one that
            // stops loudly.
            log.error("Audit entry could not be written: {}", failed.getMessage(), failed);
        }
    }

    /**
     * The entry and what its listeners write, in one transaction — or, if that fails, the entry alone.
     *
     * <p><b>Once apart, whatever failed.</b> After a rollback nothing tells a listener's failure from
     * the entry's own, and telling them apart is not needed: the entry is written again without the
     * listeners in its transaction, and if that fails too the failure was the entry's. What an
     * entry refused twice costs is one more statement; what a listener's failure would have cost
     * without this is the entry.
     */
    private void writeWithItsEffects(Record entry) {
        if (listeners.isEmpty()) {
            writeRetryingOnLocks(entry, false);
            return;
        }
        try {
            writeRetryingOnLocks(entry, true);
        } catch (RuntimeException together) {
            log.warn("Audit entry {} and its listeners' writes could not commit together; writing the entry alone: {}",
                    entry.operation(), together.getMessage());
            writeRetryingOnLocks(entry, false);
        }
    }

    /**
     * Appends an entry, and <b>throws</b> when it cannot be written — for a caller that retries, which
     * {@link #record} never lets know.
     *
     * <p>The outbox's handlers: an entry queued in the transaction of what it describes, and written
     * here by the relay (decision 0033). Swallowed as {@code record} swallows a failure, the relay would
     * mark the message delivered and the entry would be lost exactly as it was before it was queued.
     */
    public void append(Record entry) {
        writeWithItsEffects(entry);
    }

    /** The pauses before each new try of an entry refused a lock; their sum bounds what it costs its caller. */
    private static final List<Duration> LOCK_BACKOFF = List.of(
            Duration.ofMillis(50), Duration.ofMillis(100), Duration.ofMillis(200),
            Duration.ofMillis(400), Duration.ofMillis(800));

    /**
     * The entry's transaction, tried again when a lock refused it — and only then.
     *
     * <p><b>A refused lock is not a refused entry.</b> The write reads the chain's head and then
     * inserts, and two writers of the chain meet there: MySQL chooses a deadlock victim or lets a
     * lock wait time out, PostgreSQL likewise. Two instances starting together lost the one-shot
     * repair's entry that way on the SQLite fixture of the time, which answered a transaction that
     * had read with {@code SQLITE_BUSY} at once — the loser's refused claim still held the lock, for
     * the milliseconds before its rollback, when the winner recorded. Each of these is gone a moment
     * later, so each is tried again, in a new transaction; any other failure is the entry's own and
     * is not.
     */
    private void writeRetryingOnLocks(Record entry, boolean withListeners) {
        for (int attempt = 0; ; attempt++) {
            try {
                separately.executeWithoutResult(status -> write(entry, withListeners));
                return;
            } catch (PessimisticLockingFailureException locked) {
                if (attempt >= LOCK_BACKOFF.size()) {
                    throw locked;
                }
                try {
                    Thread.sleep(LOCK_BACKOFF.get(attempt));
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    throw locked;
                }
            }
        }
    }

    private void write(Record entry, boolean withListeners) {
        lockChain.run();
        Optional<AuditLogEntity> head = entries.findTopByOrderByTimestampDescIdDesc();
        String previousHash = head.map(AuditLogEntity::getEntryHash).orElse(null);

        AuditLogEntity row = new AuditLogEntity();
        // Set here rather than left to a column default: the hash covers the timestamp, and
        // a value applied by the database after the computation would make every entry fail
        // its own verification.
        row.setTimestamp(after(head, monotonicNow()));
        row.setOperationType(entry.operation().wireName());
        row.setResourceId(truncate(String.valueOf(entry.resourceId()), TEXT_COLUMN));
        row.setDescription(truncate(entry.description(), TEXT_COLUMN));
        row.setUserId(truncate(entry.userId(), TEXT_COLUMN));
        row.setIpAddress(truncate(blankToNull(entry.ipAddress()), ADDRESS_COLUMN));
        row.setUserAgent(truncate(blankToNull(entry.userAgent()), TEXT_COLUMN));
        row.setPreviousHash(previousHash);
        row.setEntryHash(AuditChain.computeEntryHash(chainEntry(row)));

        entries.saveAndFlush(row);

        Record stored = new Record(
                entry.operation(),
                // The caller's, not the column's: the column holds String.valueOf, so an absent
                // resource is the four letters "null" there, which a SOC would read as a name.
                entry.resourceId(),
                row.getDescription(),
                row.getUserId(),
                row.getIpAddress(),
                row.getUserAgent(),
                entry.signal());

        // **Before the mirror.** A listener that throws aborts this transaction, and the entry is
        // written again on its own: had the mirror line gone first, it would hold the aborted
        // attempt too, an entry the table never kept.
        if (withListeners) {
            listeners.forEach(listener -> listener.recordedInTransaction(stored, row.getTimestamp()));
        }

        // **Mirrored before this transaction commits, deliberately.** A rollback after the
        // line is written leaves the mirror holding an entry the table never kept, which
        // `verifyAgainstMirror` reports as unrecorded — noise. Writing after the commit
        // instead would leave the opposite: an action that rolled the transaction back could
        // keep an entry out of the mirror entirely, which is the case the mirror exists for.
        // Noise that can be explained beats a hole that cannot.
        if (!mirror.append(mirrored(row))) {
            log.error("Audit entry {} is in the table but not in the mirror", row.getId());
        }

        if (!withListeners) {
            afterCommit(stored, row.getTimestamp());
        }
    }

    @Transactional(readOnly = true)
    public List<AuditLogEntity> recent(int limit) {
        return entries.findRecent(org.springframework.data.domain.Limit.of(limit));
    }

    /**
     * How many recent entries the compliance summary checks.
     *
     * <p>Enough that tampering with something an operator did today is caught, small enough that
     * the check costs one indexed read.
     */
    private static final int RECENT_INTEGRITY_WINDOW = 500;

    /**
     * The integrity of the most recent entries, without reading the table.
     *
     * <p><b>Why this exists.</b> {@link #verify()} says of itself that it reads the whole table
     * and is "a deliberate verification, not something done on every page render" — and the
     * compliance summary was doing exactly that, on a table that is the largest one a mature
     * instance has, on every page load.
     *
     * <p><b>What it checks, and what it deliberately does not.</b> Each entry in the window is
     * rehashed from its own fields and compared to the hash it stores: that is what detects a
     * <em>modified</em> row, which is the realistic threat and the one the chain exists for. It
     * does <b>not</b> check that predecessors still exist, because a window cannot — an entry at
     * the edge legitimately points at one outside it, and reporting that would be an alarm
     * raised by the boundary rather than by the log. Deletion detection stays with
     * {@link #verify()} and, for the case the chain cannot see at all, with the mirror.
     *
     * <p>So a {@code false} here means "a recent entry no longer matches its own hash", which is
     * a real finding. A {@code true} means "nothing recent was altered", not "the log is
     * provably whole" — and §5.1 of the compliance document says so to the reader who acts on it.
     */
    @Transactional(readOnly = true)
    public boolean recentEntriesMatchTheirHashes() {
        for (AuditLogEntity row : entries.findRecent(org.springframework.data.domain.Limit.of(RECENT_INTEGRITY_WINDOW))) {
            String stored = row.getEntryHash();
            if (stored == null || stored.isBlank()) {
                // Predates the chaining. Counting it as a break would report an alarm about a
                // row nobody ever claimed was covered — the same reasoning as verifyChain's.
                continue;
            }
            if (!stored.equals(AuditChain.computeEntryHash(verifiable(row).entry()))) {
                return false;
            }
        }
        return true;
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
     * Whether a second copy exists at all — the question, without the comparison.
     *
     * <p>{@link #verifyAgainstMirror()} reads the whole mirror file and every audit row, which is
     * the right cost for an integrity check somebody asked for and the wrong one for a caller
     * that only needs to know whether the control is switched on. The compliance summary is that
     * caller, and it runs on every page load.
     */
    public boolean mirrorConfigured() {
        return mirror.configured();
    }

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

    /**
     * The fallback: tells the listeners once this transaction has committed, or at once when there is
     * none — a unit test calling this class directly. Reached only for an entry written apart from
     * its listeners' writes, see {@link #writeWithItsEffects}.
     *
     * <p>What they receive is the entry as stored: the description truncated to its column, the
     * blank address and user agent as null. An event forwarded to a SOC then says what the audit log
     * says, and not what the caller happened to pass.
     */
    private void afterCommit(Record stored, Instant at) {
        if (listeners.isEmpty()) {
            return;
        }
        Runnable notify = () -> listeners.forEach(listener -> {
            try {
                listener.recorded(stored, at);
            } catch (RuntimeException failed) {
                // Spring hands an after-commit exception to whoever committed: the audited action.
                // The entry is committed already; a listener's failure is logged and stops there.
                log.error("Audit listener {} failed on {}: {}",
                        listener.getClass().getSimpleName(), stored.operation(), failed.getMessage(), failed);
            }
        });
        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override
                public void afterCommit() {
                    notify.run();
                }
            });
        } else {
            notify.run();
        }
    }

    /**
     * Later than the head, whichever instance wrote it. The verification follows the chain in timestamp
     * order, and the lock orders the writers but not their clocks: an instance whose clock runs a
     * millisecond behind another's would date its entry before the head it chains onto, and the
     * verification would read the two in the wrong order and report a break.
     */
    private static Instant after(Optional<AuditLogEntity> head, Instant candidate) {
        return head.map(AuditLogEntity::getTimestamp)
                .filter(newest -> !candidate.isAfter(newest))
                .map(newest -> newest.plusMillis(1))
                .orElse(candidate);
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
                com.asmolabs.vectispire.common.domain.crypto.Digests.canonical(row.getTimestamp()),
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

    private static String truncate(String value, int width) {
        if (value == null || value.length() <= width) {
            return value;
        }
        // Never half a surrogate pair: a lone high surrogate is not UTF-8, and an engine may refuse
        // the row for it — the failure this cut exists to prevent.
        int end = Character.isHighSurrogate(value.charAt(width - 1)) ? width - 1 : width;
        return value.substring(0, end);
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value;
    }
}
