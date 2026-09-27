package com.asmolabs.vectispire.core.threatintel;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.siem.CefEvent;
import com.asmolabs.vectispire.common.domain.siem.SecurityEventType;
import com.asmolabs.vectispire.common.domain.threatintel.KevCatalog;
import com.asmolabs.vectispire.common.domain.threatintel.ThreatIntelRecord;
import com.asmolabs.vectispire.common.domain.threatintel.ThreatIntelSyncStatus;
import com.asmolabs.vectispire.common.domain.threatintel.ThreatIntelSyncStatus.State;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.audit.RequestActor;
import com.asmolabs.vectispire.core.issues.IssueCatalog;
import com.asmolabs.vectispire.core.issues.IssueView;
import com.asmolabs.vectispire.core.siem.SiemEvents;
import com.asmolabs.vectispire.core.threatintel.internal.KevCatalogSource;
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
 * The CISA KEV catalogue, synchronised and stored, and the backlog's exploitation re-evaluated
 * against it.
 *
 * <p><b>It was a list of ten records typed into this class</b>, upserted by a "synchronisation"
 * that fetched nothing — KEV flags dated 2024-01-01 whatever the day CISA listed them, EPSS figures
 * no feed published, a placeholder identifier — and served as a fallback by every lookup. {@code
 * CRITICAL_KEV_DETECTED} could only ever fire for those ten, and a CVE CISA added yesterday was
 * never announced. The list is gone rather than kept as a fallback: a fallback to stale data is
 * silent by construction, and an installation that cannot reach CISA says so — {@link
 * State#NEVER_SYNCED} or {@link State#FAILED}, with the reason — and reads a mirror instead
 * ({@code vectispire.threat-intel.kev-url}).
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
    private final TransactionTemplate transactions;
    private final Clock clock;

    public ThreatIntelFeedService(
            ThreatIntelRepository intelRepo,
            ThreatIntelSyncRepository syncRepo,
            IssueCatalog issuesRepo,
            SiemEvents siemEvents,
            AuditLogService audit,
            KevCatalogSource catalogue,
            TransactionTemplate transactions,
            Clock clock) {
        this.intelRepo = intelRepo;
        this.syncRepo = syncRepo;
        this.issuesRepo = issuesRepo;
        this.siemEvents = siemEvents;
        this.audit = audit;
        this.catalogue = catalogue;
        this.transactions = transactions;
        this.clock = clock;
    }

    public ThreatIntelSyncStatus getStatus() {
        return syncRepo.findById(ThreatIntelSyncEntity.SINGLETON_ID)
                .map(sync -> status(sync, 0))
                .orElseGet(() -> new ThreatIntelSyncStatus(null, 0, 0, State.NEVER_SYNCED, 0, null, null, null, null));
    }

    /**
     * A synchronisation somebody asked for, audited once it has committed.
     *
     * <p><b>No transaction is open while the catalogue is fetched.</b> The fetch reads a megabyte and
     * a half from CISA or a mirror, ten seconds at worst; the write that follows is one short
     * transaction. The audit entry opens its own transaction, and inside the sync's it would wait on
     * the parent's lock on SQLite, where the lock is the file; so it is written after both.
     *
     * <p><b>The one way in.</b> The EPSS screen's sync called the unaudited body directly, so the same
     * outbound call and the same re-evaluation of the backlog left an entry from one screen and none
     * from the other. The body is private; both routes and the schedule come through here, and a
     * failed attempt is audited as one — the outbound call was made either way.
     */
    public ThreatIntelSyncStatus syncThreatIntel(RequestActor actor, Origin origin) {
        ThreatIntelSyncStatus result = synchronize();
        audit.record(actor.entry(AuditOperation.THREAT_INTEL_SYNCED, "threat_intel", describe(result, origin)));
        return result;
    }

    /**
     * The scheduled synchronisation, when one is due and this instance won it.
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
        return Optional.of(syncThreatIntel(SCHEDULE, Origin.SCHEDULE));
    }

    /** The fetch, outside any transaction, then the write, in one. */
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
        return transactions.execute(status -> apply(read, attempted));
    }

    /** Within the transaction {@link #synchronize()} opens. */
    private ThreatIntelSyncStatus recordFailure(Instant attempted, String reason) {
        ThreatIntelSyncEntity sync = holdSyncRow(attempted);
        sync.setStatus(State.FAILED.name());
        sync.setLastError(reason);
        return status(syncRepo.save(sync), 0);
    }

    /** Within the transaction {@link #synchronize()} opens: the catalogue stored, then the backlog. */
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
        read.added().forEach((cve, added) -> {
            ThreatIntelEntity entity = stored.get(cve);
            if (entity == null) {
                entity = new ThreatIntelEntity();
                entity.setCveId(cve);
                stored.put(cve, entity);
            } else if (entity.isKev() && Objects.equals(entity.getDateAdded(), added)) {
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
        intelRepo.saveAll(changed);

        long updatedIssues = reevaluate(stored);

        sync.setLastSyncedAt(now);
        sync.setCveCount(stored.size());
        sync.setKevCount(read.added().size());
        sync.setStatus(State.SYNCED.name());
        sync.setKevCatalogVersion(read.version());
        sync.setKevReleasedAt(read.released());
        sync.setLastError(null);
        return status(syncRepo.save(sync), updatedIssues);
    }

    /**
     * The open issues' exploitation, against the catalogue just stored.
     *
     * <p><b>Two queries, not one plus one per issue.</b> This read the whole of {@code t_issue} and
     * filtered the closed rows in Java, then asked the intel table for one CVE at a time. The state
     * filter is SQL, and the intel is the map already in memory. What is unchanged on purpose is which
     * issues qualify — "not closed and not resolved", passed as data so the definition stays the
     * caller's.
     *
     * <p><b>Absent from the catalogue is not exploited</b>, since the catalogue applied is whole: an
     * issue flagged by an older catalogue, or by the typed-in list this replaced, is un-flagged.
     * The EPSS score is only ever replaced by a known one, as on a scan.
     */
    private long reevaluate(Map<String, ThreatIntelEntity> intel) {
        List<IssueView> open = issuesRepo.notInStates(List.of("closed", "resolved"));

        // The figures are this module's decision; the rows are the backlog's, written in one batch
        // after the loop, in this transaction (decision 0029).
        List<IssueCatalog.Exploitation> updates = new ArrayList<>();
        for (IssueView issue : open) {
            if (issue.identifier() == null || issue.identifier().isBlank()) {
                continue;
            }
            ThreatIntelEntity match = intel.get(issue.identifier().trim().toUpperCase(Locale.ROOT));
            boolean kev = match != null && match.isKev();
            Double epss = match != null && match.getEpssScore() != null ? match.getEpssScore() : issue.epssScore();
            if (kev == issue.isKev() && Objects.equals(epss, issue.epssScore())) {
                continue;
            }
            updates.add(new IssueCatalog.Exploitation(issue.id(), kev, epss));

            if (kev && !issue.isKev()) {
                log.warn("CVE {} newly listed as actively exploited in the CISA KEV catalogue. Notifying SOC/SIEM.",
                        issue.identifier());
                // Queued in this transaction, sent after it commits: a reclassification that rolls
                // back announces nothing, and no collector holds this sync's locks while it answers.
                siemEvents.enqueue(CefEvent.builder(SecurityEventType.CRITICAL_KEV_DETECTED)
                        .message("Vulnerability " + issue.identifier()
                                + " promoted to CISA Known Exploited Vulnerability (KEV)")
                        .target(targetOf(issue))
                        .identifier(issue.identifier())
                        .component(issue.packageName())
                        .build());
            }
        }
        issuesRepo.recordExploitation(updates);
        return updates.size();
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
                sync.getLastError());
    }

    private static String describe(ThreatIntelSyncStatus result, Origin origin) {
        return result.status() == State.SYNCED
                ? "CISA KEV catalogue synchronized from " + origin.phrase + " (version "
                        + (result.kevCatalogVersion() == null ? "unstated" : result.kevCatalogVersion())
                        + ", KEV=" + result.totalKev() + ", updated=" + result.backlogUpdatedCount() + ")"
                : "CISA KEV catalogue synchronization from " + origin.phrase + " failed: " + result.lastError()
                        + " (catalogue in use kept, KEV=" + result.totalKev() + ")";
    }

    private static String reason(RuntimeException failure) {
        return truncate(failure.getMessage() == null ? failure.getClass().getSimpleName() : failure.getMessage());
    }

    private static String truncate(String message) {
        return message.length() <= ERROR_MAX ? message : message.substring(0, ERROR_MAX - 1) + "…";
    }

    /** The target a finding belongs to, as the CEF target field names it: {@code repository 12}, {@code container 3}. */
    private static String targetOf(IssueView issue) {
        if (issue.repoId() != null) {
            return "repository " + issue.repoId();
        }
        return issue.containerId() == null ? null : "container " + issue.containerId();
    }

    /** What the feed recorded about one CVE; empty when it recorded nothing — which is not "not exploited" before a sync. */
    public Optional<ThreatIntelRecord> lookupCve(String cveId) {
        if (cveId == null || cveId.isBlank()) return Optional.empty();
        return intelRepo.findByCveIdIgnoreCase(cveId.trim()).map(ThreatIntelFeedService::record);
    }

    /**
     * The intel for many CVE ids in one query.
     *
     * <p><b>Why this exists.</b> The fleet summary asked {@code lookupCve} once per open issue,
     * which is one {@code select} per row: 468 queries for 620 issues, measured. The answer was
     * always the same shape — a map from id to record — so the loop was paying per item for a
     * lookup that a single {@code in} clause answers. Keyed lower-case because the feed and the
     * scanners do not agree on case — the same reason {@code findByCveIdInIgnoreCase} is
     * hand-written JPQL.
     *
     * <p>What the table holds and nothing else: the ten typed-in records this used to fall back to
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

        Map<String, ThreatIntelRecord> found = new HashMap<>();
        for (ThreatIntelEntity e : intelRepo.findByCveIdInIgnoreCase(wanted)) {
            found.put(e.getCveId().toLowerCase(Locale.ROOT), record(e));
        }
        return Map.copyOf(found);
    }

    private static ThreatIntelRecord record(ThreatIntelEntity e) {
        return new ThreatIntelRecord(
                e.getCveId(),
                e.isKev(),
                e.getEpssScore(),
                e.getEpssPercentile(),
                e.getDateAdded(),
                e.isKev() ? "Listed in the CISA KEV catalogue" : "No longer listed in the CISA KEV catalogue");
    }
}
