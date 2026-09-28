package com.asmolabs.vectispire.core.threatintel;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.enrichment.Catalogs;
import com.asmolabs.vectispire.common.domain.siem.CefEvent;
import com.asmolabs.vectispire.common.domain.siem.SecurityEventType;
import com.asmolabs.vectispire.common.domain.threatintel.Exploitation;
import com.asmolabs.vectispire.common.domain.threatintel.KevCatalog;
import com.asmolabs.vectispire.common.domain.threatintel.KevListing;
import com.asmolabs.vectispire.common.domain.threatintel.ThreatIntelRecord;
import com.asmolabs.vectispire.common.domain.threatintel.ThreatIntelSyncStatus;
import com.asmolabs.vectispire.common.domain.threatintel.ThreatIntelSyncStatus.EpssFeedStatus;
import com.asmolabs.vectispire.common.domain.threatintel.ThreatIntelSyncStatus.State;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.audit.RequestActor;
import com.asmolabs.vectispire.core.issues.IssueCatalog;
import com.asmolabs.vectispire.core.issues.persistence.queries.IssueRows;
import com.asmolabs.vectispire.core.siem.SiemEvents;
import com.asmolabs.vectispire.core.threatintel.internal.EpssFeed;
import com.asmolabs.vectispire.core.threatintel.internal.KevCatalogSource;
import com.asmolabs.vectispire.core.threatintel.persistence.KnownEpssScore;
import com.asmolabs.vectispire.core.threatintel.persistence.ThreatIntelBulkWrites;
import com.asmolabs.vectispire.core.threatintel.persistence.ThreatIntelEntity;
import com.asmolabs.vectispire.core.threatintel.persistence.ThreatIntelRepository;
import com.asmolabs.vectispire.core.threatintel.persistence.ThreatIntelSyncEntity;
import com.asmolabs.vectispire.core.threatintel.persistence.ThreatIntelSyncRepository;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * The two synchronised feeds — the CISA KEV catalogue and FIRST's EPSS file — and the backlog
 * re-evaluated against them. The catalogue is written here; the EPSS file by {@link EpssFeed}, which
 * this class calls and audits.
 *
 * <p><b>The catalogue was a list of ten records typed into this class</b>, upserted by a
 * "synchronisation" that fetched nothing — KEV flags dated 2024-01-01 whatever the day CISA listed
 * them, EPSS figures no feed published, a placeholder identifier — and served as a fallback by every
 * lookup. {@code CRITICAL_KEV_DETECTED} could only ever fire for those ten, and a CVE CISA added
 * yesterday was never announced. The list is gone rather than kept as a fallback: a fallback to
 * stale data is silent by construction, and an installation that cannot reach CISA says so — {@link
 * State#NEVER_SYNCED} or {@link State#FAILED}, with the reason — and reads a mirror instead ({@code
 * vectispire.threat-intel.kev-url}). The EPSS file follows the same rules ({@code epss-url}).
 *
 * <p><b>The catalogue is a replacement, not a delta.</b> A CVE it does not list is not exploited
 * as far as this feed knows, and an open issue flagged exploited is un-flagged when its CVE leaves
 * it — or was never in it, as the typed-in placeholder was not. That is why only a whole catalogue
 * is applied ({@link KevCatalog}), and why one older than the catalogue in use is refused.
 */
@Service
public class ThreatIntelFeedService {

    private static final Logger log = LoggerFactory.getLogger(ThreatIntelFeedService.class);

    /**
     * How old the catalogue in use may get before the schedule reads it again. CISA publishes on
     * working days, sometimes twice; six hours bounds how late a newly listed CVE is announced to
     * the SIEM, for four downloads of a megabyte and a half a day.
     */
    static final Duration REFRESH_AFTER = Duration.ofHours(6);

    /**
     * How long after a failed attempt the schedule tries again. Under the hourly turn, so that the
     * turn's own drift never makes it skip one; above zero, so several instances ask once between
     * them rather than once each.
     */
    static final Duration RETRY_AFTER = Duration.ofMinutes(30);

    /** The column {@code last_error} is 500. */
    private static final int ERROR_MAX = 500;

    /** Identifiers per lookup, under every engine's bind-parameter ceiling. */
    private static final int LOOKUP_BATCH = 1_000;

    /** Open issues re-evaluated per transaction, as the EPSS refresh re-scores them. */
    static final int BACKLOG_PAGE = 500;

    /** The states the re-evaluation treats as settled: "still open" is every other one. */
    private static final List<String> CLOSED = List.of("closed", "resolved");

    /** The actor of a synchronisation nobody asked for, as the audit log names it. */
    private static final RequestActor SCHEDULE = new RequestActor("system", null, null);

    /** Where a synchronisation was asked from, as its audit entry says. */
    public enum Origin {
        THREAT_INTELLIGENCE_SCREEN("the threat intelligence screen"),
        EPSS_SCREEN("the EPSS screen"),
        SCHEDULE("the maintenance schedule");

        private final String phrase;

        Origin(String phrase) {
            this.phrase = phrase;
        }
    }

    private final ThreatIntelRepository intelRepo;
    private final ThreatIntelSyncRepository syncRepo;
    private final IssueCatalog issuesRepo;
    private final SiemEvents siemEvents;
    private final AuditLogService audit;
    private final KevCatalogSource catalogue;
    private final EpssFeed epss;
    private final TransactionTemplate transactions;
    private final Clock clock;

    public ThreatIntelFeedService(
            ThreatIntelRepository intelRepo,
            ThreatIntelSyncRepository syncRepo,
            IssueCatalog issuesRepo,
            SiemEvents siemEvents,
            AuditLogService audit,
            KevCatalogSource catalogue,
            EpssFeed epss,
            TransactionTemplate transactions,
            Clock clock) {
        this.intelRepo = intelRepo;
        this.syncRepo = syncRepo;
        this.issuesRepo = issuesRepo;
        this.siemEvents = siemEvents;
        this.audit = audit;
        this.catalogue = catalogue;
        this.epss = epss;
        this.transactions = transactions;
        this.clock = clock;
    }

    public ThreatIntelSyncStatus getStatus() {
        return syncRepo.findById(ThreatIntelSyncEntity.SINGLETON_ID)
                .map(sync -> status(sync, 0))
                .orElseGet(() -> new ThreatIntelSyncStatus(
                        null, 0, 0, State.NEVER_SYNCED, 0, null, null, null, null, EpssFeedStatus.never()))
                .withEpss(epss.status());
    }

    /**
     * A synchronisation somebody asked for — the catalogue, then the EPSS file — each audited once it
     * has committed.
     *
     * <p><b>No transaction is open while a feed is fetched.</b> The catalogue is a megabyte and a
     * half, the EPSS file some three; the writes that follow are short transactions. The audit entry
     * opens its own transaction, and inside the sync's it would wait on the parent's lock on SQLite,
     * where the lock is the file; so it is written after.
     *
     * <p><b>The one way in.</b> The EPSS screen's sync called the unaudited body directly, so the same
     * outbound call and the same re-evaluation of the backlog left an entry from one screen and none
     * from the other. The bodies are private or internal; both routes and the schedule come through
     * here, and a failed attempt is audited as one — the outbound call was made either way.
     *
     * <p><b>Both feeds, one entry each.</b> They are fetched from different places and fail for
     * different reasons; one entry per feed says which was read, and why the other was not.
     */
    public ThreatIntelSyncStatus syncThreatIntel(RequestActor actor, Origin origin) {
        ThreatIntelSyncStatus kev = synchronize();
        audit.record(actor.entry(AuditOperation.THREAT_INTEL_SYNCED, "threat_intel", describe(kev, origin)));
        EpssFeed.Attempt scored = epss.sync();
        audit.record(actor.entry(AuditOperation.THREAT_INTEL_SYNCED, "threat_intel", describe(scored, origin)));
        return kev.withEpss(scored.status());
    }

    /**
     * The scheduled catalogue synchronisation, when one is due and this instance won it.
     *
     * <p>Called every hourly turn on every instance; the claim decides whether anything happens
     * ({@link ThreatIntelSyncRepository#claimScheduled}). Empty when not due, or due and taken by
     * another instance.
     */
    public Optional<ThreatIntelSyncStatus> syncIfDue() {
        Instant now = clock.instant();
        boolean claimed = syncRepo.claimScheduled(
                        ThreatIntelSyncEntity.SINGLETON_ID, now, now.minus(REFRESH_AFTER), now.minus(RETRY_AFTER))
                > 0;
        if (!claimed && syncRepo.existsById(ThreatIntelSyncEntity.SINGLETON_ID)) {
            return Optional.empty();
        }
        ThreatIntelSyncStatus kev = synchronize();
        audit.record(SCHEDULE.entry(AuditOperation.THREAT_INTEL_SYNCED, "threat_intel", describe(kev, Origin.SCHEDULE)));
        return Optional.of(kev.withEpss(epss.status()));
    }

    /**
     * The scheduled EPSS synchronisation, when one is due and this instance won it — daily, where the
     * catalogue's is every six hours: FIRST publishes once a day. Audited as a lead's is.
     */
    public Optional<ThreatIntelSyncStatus> syncEpssIfDue() {
        return epss.syncIfDue().map(scored -> {
            audit.record(SCHEDULE.entry(
                    AuditOperation.THREAT_INTEL_SYNCED, "threat_intel", describe(scored, Origin.SCHEDULE)));
            return getStatus().withEpss(scored.status());
        });
    }

    /**
     * The fetch, outside any transaction; the catalogue written in one; then the backlog, a page per
     * transaction.
     *
     * <p><b>Applied once stored.</b> What follows cannot un-apply the catalogue: a page that fails is
     * logged, and the next synchronisation walks the whole backlog again — the flags are compared, not
     * toggled, so a page applied twice changes nothing and announces nothing.
     */
    private ThreatIntelSyncStatus synchronize() {
        Instant attempted = clock.instant();
        KevCatalog read;
        try {
            read = catalogue.fetch();
        } catch (RuntimeException failure) {
            // The catalogue in use stays: an outage is not a catalogue that lists nothing. What
            // changes is the status, so a stale flag is visible as stale rather than trusted.
            String reason = reason(failure);
            log.warn("KEV catalogue not synchronised from {}: {}", catalogue.location(), reason);
            return transactions.execute(status -> recordFailure(attempted, reason));
        }
        ThreatIntelSyncStatus stored = transactions.execute(status -> apply(read, attempted));
        if (stored.status() != State.SYNCED) {
            return stored;
        }
        long updated = 0;
        try {
            updated = reevaluate();
        } catch (RuntimeException failure) {
            log.warn("KEV catalogue applied, but the open issues were not all re-evaluated: {}", reason(failure));
        }
        return stored.withBacklogUpdated(updated);
    }

    /** Within the transaction {@link #synchronize()} opens. */
    private ThreatIntelSyncStatus recordFailure(Instant attempted, String reason) {
        ThreatIntelSyncEntity sync = holdSyncRow(attempted);
        sync.setStatus(State.FAILED.name());
        sync.setLastError(reason);
        return status(syncRepo.save(sync), 0);
    }

    /** Within the transaction {@link #synchronize()} opens: the catalogue stored, and the sync row. */
    private ThreatIntelSyncStatus apply(KevCatalog read, Instant attempted) {
        ThreatIntelSyncEntity sync = holdSyncRow(attempted);

        // **A catalogue older than the one in use is refused.** A mirror restored from last month's
        // copy would otherwise un-flag every CVE listed since, on the word of a document CISA itself
        // has replaced.
        if (read.released() != null && sync.getKevReleasedAt() != null && read.released().isBefore(sync.getKevReleasedAt())) {
            return recordFailure(attempted, truncate("the catalogue read (released " + read.released()
                    + ") is older than the one in use (released " + sync.getKevReleasedAt() + "); kept the newer"));
        }

        Instant now = clock.instant();
        Map<String, ThreatIntelEntity> stored = intelRepo.findAll().stream()
                .collect(Collectors.toMap(e -> e.getCveId().toUpperCase(Locale.ROOT), Function.identity(), (a, b) -> a));
        List<ThreatIntelEntity> changed = new ArrayList<>();
        // New entries many to a statement: through saveAll each was a select and an insert, 3,000
        // round trips for the first synchronisation of an installation (ThreatIntelBulkWrites).
        List<ThreatIntelBulkWrites.Listing> listed = new ArrayList<>();
        read.added().forEach((cve, added) -> {
            ThreatIntelEntity entity = stored.get(cve);
            if (entity == null) {
                listed.add(new ThreatIntelBulkWrites.Listing(cve, added));
                entity = new ThreatIntelEntity();
                entity.setCveId(cve);
                entity.setKev(true);
                entity.setDateAdded(added);
                stored.put(cve, entity);
                return;
            }
            if (entity.isKev() && Objects.equals(entity.getDateAdded(), added)) {
                return;
            }
            entity.setKev(true);
            entity.setDateAdded(added);
            entity.setUpdatedAt(now);
            changed.add(entity);
        });
        // Delisted: kept as a row, no longer as exploited — what the catalogue says today.
        stored.forEach((cve, entity) -> {
            if (entity.isKev() && !read.added().containsKey(cve)) {
                entity.setKev(false);
                entity.setUpdatedAt(now);
                changed.add(entity);
            }
        });
        intelRepo.insertListed(listed, now);
        intelRepo.saveAll(changed);

        sync.setLastSyncedAt(now);
        sync.setCveCount(stored.size());
        sync.setKevCount(read.added().size());
        sync.setStatus(State.SYNCED.name());
        sync.setKevCatalogVersion(read.version());
        sync.setKevReleasedAt(read.released());
        sync.setLastError(null);
        return status(syncRepo.save(sync), 0);
    }

    /**
     * The open issues' exploitation, against the catalogue stored, a page of {@value #BACKLOG_PAGE} at a
     * time in id order — each page its own short transaction.
     *
     * <p><b>Not the whole backlog in one transaction.</b> This read every open issue into memory in the
     * catalogue's transaction and held the sync row's lock, and SQLite's whole file, until the last
     * one was written — hundreds of thousands of rows on a large estate. Walked by keyset, each page
     * costs the same however deep the walk is, as the EPSS refresh's does.
     *
     * <p><b>Announced once.</b> Each page takes the sync row's lock before it reads its issues ({@link
     * ThreatIntelSyncRepository#holdForReevaluation}), so a second synchronisation's page reads the
     * flags the first one's committed: a newly listed CVE raises {@code CRITICAL_KEV_DETECTED} once per
     * issue, whoever walks the backlog second.
     *
     * <p><b>Absent from the catalogue is not exploited</b>, since the catalogue applied is whole: an
     * issue flagged by an older catalogue, or by the typed-in list this replaced, is un-flagged.
     *
     * <p><b>The flag only.</b> Written by a targeted update ({@link IssueCatalog#recordExploitation}): a
     * row saved whole would put back the EPSS score, or a scan's {@code lastSeenAt}, it was read with.
     */
    private long reevaluate() {
        long after = 0;
        long updated = 0;
        while (true) {
            long from = after;
            Page page = transactions.execute(status -> reevaluatePage(from));
            updated += page.updated();
            if (page.read() < BACKLOG_PAGE) {
                return updated;
            }
            after = page.last();
        }
    }

    /** One page's outcome: the rows read, the last id, the flags changed. */
    private record Page(int read, long last, int updated) {}

    /** Within its own transaction: the lock, the page, the catalogue's word on it, the flags written. */
    private Page reevaluatePage(long after) {
        syncRepo.holdForReevaluation(ThreatIntelSyncEntity.SINGLETON_ID);
        List<IssueRows.KevCandidate> page =
                issuesRepo.openIdentifiedAfter(after, CLOSED, BACKLOG_PAGE, IssueRows.KevCandidate.class);
        if (page.isEmpty()) {
            return new Page(0, after, 0);
        }
        Set<String> listed = listedAmong(page.stream().map(IssueRows.KevCandidate::identifier).toList());

        // The figures are this module's decision; the rows are the backlog's (decision 0029).
        List<IssueCatalog.Exploitation> updates = new ArrayList<>();
        for (IssueRows.KevCandidate issue : page) {
            if (issue.identifier().isBlank()) {
                continue;
            }
            boolean kev = listed.contains(issue.identifier().trim().toUpperCase(Locale.ROOT));
            boolean was = Boolean.TRUE.equals(issue.isKev());
            if (kev == was) {
                continue;
            }
            updates.add(new IssueCatalog.Exploitation(issue.id(), kev));

            if (kev) {
                log.warn("CVE {} newly listed as actively exploited in the CISA KEV catalogue. Notifying SOC/SIEM.",
                        issue.identifier());
                // Queued in this transaction, sent after it commits: a page that rolls back announces
                // nothing, and no collector holds this sync's locks while it answers.
                siemEvents.enqueue(CefEvent.builder(SecurityEventType.CRITICAL_KEV_DETECTED)
                        .message("Vulnerability " + issue.identifier()
                                + " promoted to CISA Known Exploited Vulnerability (KEV)")
                        .target(targetOf(issue.repoId(), issue.containerId()))
                        .identifier(issue.identifier())
                        .component(issue.packageName())
                        .build());
            }
        }
        issuesRepo.recordExploitation(updates);
        return new Page(page.size(), page.getLast().id(), updates.size());
    }

    /** Those of these identifiers the stored catalogue lists, upper-case — one page's, so one statement. */
    private Set<String> listedAmong(List<String> identifiers) {
        List<String> wanted = identifiers.stream()
                .map(id -> id.trim().toLowerCase(Locale.ROOT))
                .filter(id -> !id.isEmpty())
                .distinct()
                .toList();
        if (wanted.isEmpty()) {
            return Set.of();
        }
        return intelRepo.exploitedAmong(wanted).stream()
                .map(id -> id.toUpperCase(Locale.ROOT))
                .collect(Collectors.toSet());
    }

    /**
     * The singleton row, with this attempt marked on it — which also holds its write lock until the
     * transaction ends, so two synchronisations never re-evaluate the backlog at once (see {@link
     * ThreatIntelSyncRepository#markAttempt}). Created when missing.
     */
    private ThreatIntelSyncEntity holdSyncRow(Instant attempted) {
        if (syncRepo.markAttempt(ThreatIntelSyncEntity.SINGLETON_ID, attempted) == 0) {
            ThreatIntelSyncEntity fresh = new ThreatIntelSyncEntity();
            fresh.setId(ThreatIntelSyncEntity.SINGLETON_ID);
            fresh.setLastAttemptAt(attempted);
            return syncRepo.saveAndFlush(fresh);
        }
        return syncRepo.findById(ThreatIntelSyncEntity.SINGLETON_ID).orElseThrow();
    }

    /** The catalogue's state; the EPSS feed's is added by the caller, which knows what it just did. */
    private static ThreatIntelSyncStatus status(ThreatIntelSyncEntity sync, long backlogUpdated) {
        return new ThreatIntelSyncStatus(
                sync.getLastSyncedAt(),
                sync.getCveCount(),
                sync.getKevCount(),
                State.of(sync.getStatus()),
                backlogUpdated,
                sync.getKevCatalogVersion(),
                sync.getKevReleasedAt(),
                sync.getLastAttemptAt(),
                sync.getLastError(),
                EpssFeedStatus.never());
    }

    private static String describe(ThreatIntelSyncStatus result, Origin origin) {
        return result.status() == State.SYNCED
                ? "CISA KEV catalogue synchronized from " + origin.phrase + " (version "
                        + (result.kevCatalogVersion() == null ? "unstated" : result.kevCatalogVersion())
                        + ", KEV=" + result.totalKev() + ", updated=" + result.backlogUpdatedCount() + ")"
                : "CISA KEV catalogue synchronization from " + origin.phrase + " failed: " + result.lastError()
                        + " (catalogue in use kept, KEV=" + result.totalKev() + ")";
    }

    /** The EPSS feed's entry: what was read, from where, and what it left in use. */
    private static String describe(EpssFeed.Attempt attempt, Origin origin) {
        EpssFeedStatus feed = attempt.status();
        String inUse = feed.modelVersion() == null
                ? "none"
                : "model " + feed.modelVersion() + ", scores of " + feed.scoreDate() + ", " + feed.totalScored() + " CVE";
        return switch (attempt.outcome()) {
            case APPLIED -> "EPSS scores synchronized from " + origin.phrase + " (" + inUse
                    + ", updated=" + feed.backlogUpdatedCount() + ")";
            case UNCHANGED -> "EPSS scores confirmed from " + origin.phrase
                    + ": the file read is the one in use (" + inUse + ")";
            case FAILED -> "EPSS scores synchronization from " + origin.phrase + " failed: " + attempt.reason()
                    + " (scores in use kept: " + inUse + ")";
            case BUSY -> "EPSS scores synchronization from " + origin.phrase
                    + " not run: another one is in progress (scores in use: " + inUse + ")";
        };
    }

    private static String reason(RuntimeException failure) {
        return truncate(failure.getMessage() == null ? failure.getClass().getSimpleName() : failure.getMessage());
    }

    private static String truncate(String message) {
        return message.length() <= ERROR_MAX ? message : message.substring(0, ERROR_MAX - 1) + "…";
    }

    /** The target a finding belongs to, as the CEF target field names it: {@code repository 12}, {@code container 3}. */
    private static String targetOf(Long repoId, Long containerId) {
        if (repoId != null) {
            return "repository " + repoId;
        }
        return containerId == null ? null : "container " + containerId;
    }

    /**
     * What the stored feeds say about one identifier's exploitation, with unknown said as such.
     *
     * <p><b>Not {@link #lookupCve}, whose record has a boolean {@code isKev}</b>: false there is
     * "not listed" once the catalogue has been read and "nobody asked" before, and only its notes
     * tell which. A caller that prints the answer — the advisor, to a reader and to a model — needs
     * the difference in the value. {@link KevListing#UNKNOWN} before the first synchronisation and
     * for an identifier that is not a CVE, which the catalogue could never list; a null score when
     * the EPSS file in use has none, or there is no file yet.
     *
     * <p>Local reads only: both feeds are synchronised whole, so asking about a CVE tells no third
     * party which ones somebody here was looking at.
     */
    public Exploitation exploitationOf(String identifier) {
        if (!Exploitation.namesACve(identifier)) {
            return Exploitation.unknown();
        }
        String id = identifier.trim().toUpperCase(Locale.ROOT);
        KnownEpssScore score = epss.scoresOf(List.of(id)).get(id);
        boolean catalogueRead = syncRepo.findById(ThreatIntelSyncEntity.SINGLETON_ID)
                .map(ThreatIntelSyncEntity::getLastSyncedAt)
                .isPresent();
        KevListing kev = !catalogueRead
                ? KevListing.UNKNOWN
                : intelRepo.exploitedAmong(List.of(id.toLowerCase(Locale.ROOT))).isEmpty()
                        ? KevListing.NOT_LISTED
                        : KevListing.LISTED;
        return new Exploitation(kev, score == null ? null : score.score());
    }

    /**
     * What the two feeds recorded about one CVE; empty when neither recorded anything — which is not
     * "not exploited" before a sync, nor a probability of zero.
     */
    public Optional<ThreatIntelRecord> lookupCve(String cveId) {
        if (cveId == null || cveId.isBlank()) return Optional.empty();
        return Optional.ofNullable(lookupCves(List.of(cveId)).get(cveId.trim().toLowerCase(Locale.ROOT)));
    }

    /**
     * The intel for many CVE ids, in one query per feed and per thousand ids.
     *
     * <p><b>Why this exists.</b> The fleet summary asked {@code lookupCve} once per open issue,
     * which is one {@code select} per row: 468 queries for 620 issues, measured. The answer was
     * always the same shape — a map from id to record — so the loop was paying per item for a
     * lookup that a single {@code in} clause answers. Keyed lower-case because the feed and the
     * scanners do not agree on case — the same reason {@code findByCveIdInIgnoreCase} is
     * hand-written JPQL. In batches, because the list is the backlog's and the engines bound a
     * statement's parameters.
     *
     * <p>What the tables hold and nothing else: the ten typed-in records this used to fall back to
     * are gone, with the reasons the class comment gives.
     */
    public Map<String, ThreatIntelRecord> lookupCves(Collection<String> cveIds) {
        Set<String> wanted = cveIds.stream()
                .filter(id -> id != null && !id.isBlank())
                .map(id -> id.trim().toLowerCase(Locale.ROOT))
                .collect(Collectors.toCollection(LinkedHashSet::new));

        if (wanted.isEmpty()) {
            return Map.of();
        }

        Map<String, ThreatIntelEntity> listed = new HashMap<>();
        for (List<String> batch : Catalogs.batches(List.copyOf(wanted), LOOKUP_BATCH)) {
            for (ThreatIntelEntity e : intelRepo.findByCveIdInIgnoreCase(batch)) {
                listed.put(e.getCveId().toLowerCase(Locale.ROOT), e);
            }
        }
        Map<String, KnownEpssScore> scored = epss.scoresOf(wanted);
        boolean catalogueRead = syncRepo.findById(ThreatIntelSyncEntity.SINGLETON_ID)
                .map(ThreatIntelSyncEntity::getLastSyncedAt)
                .isPresent();

        Map<String, ThreatIntelRecord> found = new HashMap<>();
        for (String id : wanted) {
            ThreatIntelEntity kev = listed.get(id);
            KnownEpssScore score = scored.get(id.toUpperCase(Locale.ROOT));
            if (kev != null || score != null) {
                found.put(id, record(kev, score, id, catalogueRead));
            }
        }
        return Map.copyOf(found);
    }

    private static ThreatIntelRecord record(ThreatIntelEntity kev, KnownEpssScore score, String id, boolean catalogueRead) {
        String notes;
        if (kev != null) {
            notes = kev.isKev() ? "Listed in the CISA KEV catalogue" : "No longer listed in the CISA KEV catalogue";
        } else {
            // Not "not exploited" before the catalogue was ever read: nobody asked yet.
            notes = catalogueRead ? "Not listed in the CISA KEV catalogue" : "CISA KEV catalogue never synchronised";
        }
        return new ThreatIntelRecord(
                kev != null ? kev.getCveId() : score.cveId(),
                kev != null && kev.isKev(),
                score == null ? null : score.score(),
                score == null ? null : score.percentile(),
                kev == null ? null : kev.getDateAdded(),
                notes);
    }
}
