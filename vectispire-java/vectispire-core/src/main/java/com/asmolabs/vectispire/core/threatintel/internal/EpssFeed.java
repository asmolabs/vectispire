package com.asmolabs.vectispire.core.threatintel.internal;

import com.asmolabs.vectispire.common.domain.enrichment.Catalogs;
import com.asmolabs.vectispire.common.domain.threatintel.EpssFile;
import com.asmolabs.vectispire.common.domain.threatintel.ThreatIntelSyncStatus.EpssFeedStatus;
import com.asmolabs.vectispire.common.domain.threatintel.ThreatIntelSyncStatus.State;
import com.asmolabs.vectispire.core.issues.IssueCatalog;
import com.asmolabs.vectispire.core.issues.persistence.queries.IssueRows;
import com.asmolabs.vectispire.core.threatintel.persistence.EpssScoreRepository;
import com.asmolabs.vectispire.core.threatintel.persistence.KnownEpssScore;
import com.asmolabs.vectispire.core.threatintel.persistence.ThreatIntelSyncEntity;
import com.asmolabs.vectispire.core.threatintel.persistence.ThreatIntelSyncRepository;
import java.io.ByteArrayInputStream;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Component;

/**
 * FIRST's EPSS file, synchronised and stored: the scores a scan and the backlog read, in place of a
 * question each scan asked {@code api.first.org}.
 *
 * <p><b>Written beside the scores in use, switched to in one statement.</b> A synchronisation claims
 * the feed ({@link ThreatIntelSyncRepository#claimEpss}), writes the whole file under a generation of
 * its own in batches of {@value #WRITE_BATCH} rows — each its own short transaction, so no lock is
 * held for the 380,000 rows and SQLite's writers wait milliseconds, not seconds — then checks it and
 * points the sync row at it ({@link ThreatIntelSyncRepository#applyEpss}). Every reader reads the
 * generation the row names: until that update commits the previous scores are the ones in use, and a
 * file refused half-way, or a synchronisation that dies, leaves nothing a reader sees. The generation
 * that was replaced, or the one that was refused, is deleted afterwards in batches.
 *
 * <p><b>The generation is random, not the next number.</b> It is also the claim's token: a
 * synchronisation whose lease ran out while it was still writing must not share a generation with the
 * one that took the lease over, or its late rows would land in — and its clean-up would delete — the
 * other's. Sixty-three random bits never meet twice.
 *
 * <p><b>Nothing here is ever silently replaced by less.</b> A file that is not whole, is older than
 * the one in use, or is markedly smaller than it ({@link EpssFile}) is refused, recorded as {@link
 * State#FAILED} with the reason, and the scores in use stay. Until the first file is applied there
 * are no scores at all, and every figure is unknown — never zero.
 */
@Component
public class EpssFeed {

    private static final Logger log = LoggerFactory.getLogger(EpssFeed.class);

    /**
     * How old the file in use may get before the schedule reads it again. FIRST publishes once a day;
     * 23 hours rather than 24 because the hourly turn drifts later each time — by the time it takes to
     * run — and a full day would slip a turn every day.
     */
    static final Duration REFRESH_AFTER = Duration.ofHours(23);

    /**
     * How long after an attempt a failed one is retried: every turn but one, under the hour for the
     * same drift, above zero so several instances ask once between them.
     */
    static final Duration RETRY_AFTER = Duration.ofMinutes(50);

    /**
     * How long a claim holds. Writing, applying and replacing FIRST's 380,000 rows was measured at 1.7 s
     * on PostgreSQL, 3 to 4.5 s on MySQL and under a second on SQLite ({@code EpssScoresIntegrationTest});
     * the download's deadline is two minutes. Half an hour covers a slow mirror and a busy engine many
     * times over, and bounds how long a crashed instance keeps the others from trying.
     */
    static final Duration LEASE = Duration.ofMinutes(30);

    /** Rows per write transaction: ten statements of {@code EpssScoreBulkWrites.ROWS_PER_STATEMENT}. */
    static final int WRITE_BATCH = 5_000;

    /** Rows per delete statement, for the same reason as the write batch. */
    static final int DELETE_BATCH = 5_000;

    /** Open issues re-scored per transaction. */
    static final int BACKLOG_PAGE = 500;

    /** Identifiers per lookup, under every engine's bind-parameter ceiling. */
    static final int LOOKUP_BATCH = 500;

    /** Never a generation: the lookup of "every generation but the one in use" before there is one. */
    private static final long NO_GENERATION = -1;

    private static final int ERROR_MAX = 500;

    /** The states the KEV re-evaluation treats as settled: the same definition of "still open". */
    private static final List<String> CLOSED = List.of("closed", "resolved");

    /** How an attempt ended, for the audit entry the caller writes. */
    public enum Outcome {
        /** A new file was written, checked and put in use. */
        APPLIED,
        /** The file read is the one in use — same model, same score date — and nothing was rewritten. */
        UNCHANGED,
        /** Nothing was replaced; the status says why. */
        FAILED,
        /** Another synchronisation holds the lease; this one did not run. */
        BUSY
    }

    /**
     * An attempt, and the state it left.
     *
     * @param reason why a failed attempt failed — carried apart from the status, which a synchronisation
     *     that lost its claim does not write: the feed then says what the one holding it did
     */
    public record Attempt(Outcome outcome, EpssFeedStatus status, String reason) {}

    private final EpssScoreRepository scores;
    private final ThreatIntelSyncRepository syncs;
    private final IssueCatalog issues;
    private final EpssFileSource source;
    private final Clock clock;

    public EpssFeed(
            EpssScoreRepository scores,
            ThreatIntelSyncRepository syncs,
            IssueCatalog issues,
            EpssFileSource source,
            Clock clock) {
        this.scores = scores;
        this.syncs = syncs;
        this.issues = issues;
        this.source = source;
        this.clock = clock;
    }

    /** Where the feed stands. */
    public EpssFeedStatus status() {
        Instant now = clock.instant();
        return syncs.findById(ThreatIntelSyncEntity.SINGLETON_ID)
                .map(sync -> new EpssFeedStatus(
                        State.of(sync.getEpssStatus()),
                        sync.getEpssSyncedAt(),
                        sync.getEpssModelVersion(),
                        sync.getEpssScoreDate(),
                        sync.getEpssGeneration() == null ? 0 : sync.getEpssCount(),
                        sync.getEpssAttemptAt(),
                        sync.getEpssError(),
                        0,
                        sync.getEpssLeaseUntil() != null && sync.getEpssLeaseUntil().isAfter(now)))
                .orElseGet(EpssFeedStatus::never);
    }

    /** A synchronisation somebody asked for — unless one is running, in which case it is not run twice. */
    public Attempt sync() {
        ensureSyncRow();
        long generation = newGeneration();
        Instant now = clock.instant();
        if (syncs.claimEpss(ThreatIntelSyncEntity.SINGLETON_ID, now, now.plus(LEASE), generation) == 0) {
            return new Attempt(Outcome.BUSY, status(), null);
        }
        return run(generation);
    }

    /** The scheduled synchronisation, when one is due and this instance won it; empty otherwise. */
    public Optional<Attempt> syncIfDue() {
        ensureSyncRow();
        long generation = newGeneration();
        Instant now = clock.instant();
        boolean claimed = syncs.claimEpssScheduled(ThreatIntelSyncEntity.SINGLETON_ID, now, now.plus(LEASE), generation,
                        now.minus(REFRESH_AFTER), now.minus(RETRY_AFTER))
                > 0;
        return claimed ? Optional.of(run(generation)) : Optional.empty();
    }

    /**
     * The scores of these identifiers in the file in use, keyed upper-case; empty before the first
     * synchronisation — unknown, which is not zero.
     */
    public Map<String, KnownEpssScore> scoresOf(Collection<String> identifiers) {
        Optional<Long> generation = syncs.findById(ThreatIntelSyncEntity.SINGLETON_ID)
                .map(ThreatIntelSyncEntity::getEpssGeneration);
        return generation.map(current -> scoresOf(current, identifiers)).orElseGet(Map::of);
    }

    /** Whether a file has ever been applied. */
    public boolean synchronised() {
        return syncs.findById(ThreatIntelSyncEntity.SINGLETON_ID)
                .map(ThreatIntelSyncEntity::getEpssGeneration)
                .isPresent();
    }

    /** Under the claim: the file fetched, written, checked and applied, then the backlog re-scored. */
    private Attempt run(long generation) {
        ThreatIntelSyncEntity before = syncs.findById(ThreatIntelSyncEntity.SINGLETON_ID).orElseThrow();
        Long current = before.getEpssGeneration();

        EpssFile.Read read;
        try {
            // Left by a synchronisation that was refused or died before it cleaned up.
            discardAllBut(current, generation);
            // Fetched whole before anything is written: no transaction and no row wait on the network.
            byte[] file = source.fetch();
            read = EpssFile.read(new ByteArrayInputStream(file), WRITE_BATCH, new Writer(before, generation));
            if (read.stopped()) {
                if (syncs.confirmEpss(ThreatIntelSyncEntity.SINGLETON_ID, generation, clock.instant()) == 0) {
                    throw new IllegalStateException("the claim on the EPSS feed ran out before the file was confirmed");
                }
                return new Attempt(Outcome.UNCHANGED, status(), null);
            }
            if (current != null) {
                EpssFile.requireComparable(before.getEpssCount(), read.rows());
            }
            long written = scores.countByGeneration(generation);
            if (written != read.rows()) {
                throw new IllegalStateException("the file carries " + read.rows() + " scores and " + written
                        + " were stored: its rows were removed while it was written, by a synchronisation that took "
                        + "over an expired claim");
            }
            if (syncs.applyEpss(ThreatIntelSyncEntity.SINGLETON_ID, generation, clock.instant(),
                            read.header().modelVersion(), read.header().scoreDate(), read.rows())
                    == 0) {
                throw new IllegalStateException("the claim on the EPSS feed ran out before the file was applied");
            }
        } catch (RuntimeException failure) {
            String reason = reason(failure);
            log.warn("EPSS file not synchronised from {}: {}", source.location(), reason);
            if (syncs.failEpss(ThreatIntelSyncEntity.SINGLETON_ID, generation, reason) == 0) {
                log.warn("EPSS synchronisation had lost its claim; the failure is left to the one that holds it.");
            }
            discardQuietly(generation);
            return new Attempt(Outcome.FAILED, status(), reason);
        }

        // Applied: what follows cannot un-apply it, and a failure below is logged and left to the next
        // synchronisation, which re-scores the backlog again.
        long rescored = 0;
        try {
            rescored = rescoreBacklog(generation);
        } catch (RuntimeException failure) {
            log.warn("EPSS file applied, but the open issues were not all re-scored: {}", reason(failure));
        }
        if (current != null) {
            discardQuietly(current);
        }
        log.info("EPSS file {} of {} synchronised: {} CVE scored, {} open issue(s) re-scored.",
                read.header().modelVersion(), read.header().scoreDate(), read.rows(), rescored);
        return new Attempt(Outcome.APPLIED, status().withBacklogUpdated(rescored), null);
    }

    /**
     * The open issues' scores, from the file just applied, a page at a time.
     *
     * <p><b>Only a known score replaces one</b>, as on a scan: a CVE the file no longer scores — a
     * rejected one — keeps the figure it had rather than losing it to an unknown.
     *
     * <p><b>Bounded pages, each its own transaction</b>, walked by id: the backlog of a large estate is
     * hundreds of thousands of rows, and read at once — as the KEV re-evaluation still reads it — it
     * would be one transaction holding all of them.
     */
    private long rescoreBacklog(long generation) {
        long after = 0;
        long rescored = 0;
        while (true) {
            List<IssueRows.EpssCandidate> page = issues.openIdentifiedAfter(after, CLOSED, BACKLOG_PAGE);
            if (page.isEmpty()) {
                return rescored;
            }
            after = page.getLast().id();

            Map<String, KnownEpssScore> known = scoresOf(generation, page.stream()
                    .map(IssueRows.EpssCandidate::identifier)
                    .toList());
            Map<Long, Double> changed = new LinkedHashMap<>();
            for (IssueRows.EpssCandidate issue : page) {
                KnownEpssScore score = known.get(normalised(issue.identifier()));
                if (score != null && !Objects.equals(score.score(), issue.epssScore())) {
                    changed.put(issue.id(), score.score());
                }
            }
            rescored += issues.recordEpss(changed);
            if (page.size() < BACKLOG_PAGE) {
                return rescored;
            }
        }
    }

    private Map<String, KnownEpssScore> scoresOf(long generation, Collection<String> identifiers) {
        // Only what can be a CVE: a secret's rule id, or a SAST rule's, would be sent for no answer.
        List<String> wanted = identifiers.stream()
                .filter(Objects::nonNull)
                .map(EpssFeed::normalised)
                .filter(id -> id.startsWith("CVE-"))
                .collect(Collectors.toCollection(LinkedHashSet::new))
                .stream()
                .toList();
        Map<String, KnownEpssScore> found = new HashMap<>();
        for (List<String> batch : Catalogs.batches(wanted, LOOKUP_BATCH)) {
            scores.scoresOf(generation, batch).forEach(score -> found.put(score.cveId(), score));
        }
        return found;
    }

    /** Checks the header against the file in use, then writes each batch under the new generation. */
    private final class Writer implements EpssFile.Sink {

        private final ThreatIntelSyncEntity inUse;
        private final long generation;

        Writer(ThreatIntelSyncEntity inUse, long generation) {
            this.inUse = inUse;
            this.generation = generation;
        }

        @Override
        public boolean header(EpssFile.Header header) {
            Instant usedDate = inUse.getEpssScoreDate();
            if (inUse.getEpssGeneration() == null || usedDate == null) {
                return true;
            }
            // **A file older than the one in use is refused.** A mirror restored from last month's copy
            // would otherwise put last month's probabilities back on every issue, on the word of a
            // file FIRST itself has replaced.
            if (header.scoreDate().isBefore(usedDate)) {
                throw new EpssFile.Unreadable("the file read (scores of " + header.scoreDate()
                        + ") is older than the one in use (scores of " + usedDate + "); kept the newer");
            }
            // The same file again — a mirror not refreshed since — is confirmed, not rewritten.
            return !(header.scoreDate().equals(usedDate) && header.modelVersion().equals(inUse.getEpssModelVersion()));
        }

        @Override
        public void batch(List<EpssFile.Score> batch) {
            scores.insertAll(generation, batch);
        }
    }

    /** Every generation but the one in use and the one being written. */
    private void discardAllBut(Long current, long writing) {
        for (long generation : scores.generationsOtherThan(current == null ? NO_GENERATION : current)) {
            if (generation != writing) {
                discard(generation);
            }
        }
    }

    private void discardQuietly(long generation) {
        try {
            discard(generation);
        } catch (RuntimeException failure) {
            // Left for the next synchronisation, which discards every generation not in use first.
            log.warn("EPSS generation {} not discarded: {}", generation, reason(failure));
        }
    }

    /**
     * Deletes one generation {@value #DELETE_BATCH} rows at a time, in key order: the row at the
     * batch's end is the boundary, and everything up to it goes in one statement — see {@link
     * EpssScoreRepository#deleteUpTo} for why not a {@code limit}.
     */
    private void discard(long generation) {
        while (true) {
            List<String> boundary = scores.cveIdsOf(generation, PageRequest.of(DELETE_BATCH - 1, 1));
            if (boundary.isEmpty()) {
                scores.deleteGeneration(generation);
                return;
            }
            scores.deleteUpTo(generation, boundary.getFirst());
        }
    }

    /** The row every attempt is recorded on; created when missing, by whichever instance gets there first. */
    private void ensureSyncRow() {
        if (syncs.existsById(ThreatIntelSyncEntity.SINGLETON_ID)) {
            return;
        }
        try {
            syncs.saveAndFlush(new ThreatIntelSyncEntity());
        } catch (DataIntegrityViolationException createdMeanwhile) {
            // Another instance, or the KEV synchronisation, created it: the claim below reads it.
        }
    }

    private static long newGeneration() {
        return ThreadLocalRandom.current().nextLong(1, Long.MAX_VALUE);
    }

    private static String normalised(String identifier) {
        return identifier == null ? "" : identifier.trim().toUpperCase(Locale.ROOT);
    }

    private static String reason(RuntimeException failure) {
        String message = failure.getMessage() == null ? failure.getClass().getSimpleName() : failure.getMessage();
        return message.length() <= ERROR_MAX ? message : message.substring(0, ERROR_MAX - 1) + "…";
    }
}
