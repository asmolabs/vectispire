package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.retention.RetentionPolicy;
import com.asmolabs.vectispire.common.domain.retention.RetentionPolicy.Candidate;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.repositories.Scans;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Purging raw scanner payloads.
 *
 * <p><b>What this version no longer does, and why.</b> The Python version ran a {@code VACUUM}
 * after every purge, because SQLite keeps its emptied pages and without it the file never
 * shrank — the operator saw no effect. PostgreSQL and MySQL reuse the space themselves, and a
 * {@code VACUUM FULL} would take an exclusive lock on the table for as long as it takes to
 * rewrite it: the cure would be worse than the disease. The space therefore goes back to the
 * engine, not to the filesystem, and that is the correct behaviour here.
 *
 * <p><b>Idempotent, therefore safe without an election.</b> Dropping the same payload twice
 * costs nothing, which is what lets the purge run in every instance.
 */
@Service
public class RetentionService {

    private static final Logger log = LoggerFactory.getLogger(RetentionService.class);

    /**
     * How many identifiers go into one {@code in} clause.
     *
     * <p>A clause of several tens of thousands exceeds some drivers' parameter limits, and
     * purging a long-neglected database is exactly the case where the list is long.
     */
    private static final int BATCH_SIZE = 500;

    private final Scans scans;
    private final SettingsService settings;
    private final Clock clock;

    public RetentionService(Scans scans, SettingsService settings, Clock clock) {
        this.scans = scans;
        this.settings = settings;
        this.clock = clock;
    }

    public RetentionPolicy policy() {
        return new RetentionPolicy(
                settings.asInt(Setting.RETENTION_KEEP_PER_TARGET),
                Duration.ofDays(settings.asInt(Setting.RETENTION_MAX_AGE_DAYS)));
    }

    /** The identifiers of the scans whose payloads can be dropped. */
    @Transactional(readOnly = true)
    public List<Long> findPrunable() {
        RetentionPolicy policy = policy();
        if (!policy.isEnabled()) {
            return List.of();
        }

        // **Only the deciding columns are read.** Loading whole entities would pull the payloads
        // themselves into memory — several megabytes per scan — in order to decide to erase
        // them, which is exactly what the purge is trying to avoid.
        List<Object[]> rows = scans.findPayloadBearing();
        List<Candidate> candidates = rows.stream()
                .map(row -> new Candidate(((Number) row[0]).longValue(), targetOf(row), (java.time.Instant) row[3]))
                .toList();

        return policy.prunable(candidates, clock.instant());
    }

    /**
     * Drops the raw payloads of every prunable scan.
     *
     * <p>Written by a bulk update rather than by {@code save}: rehydrating each entity to set
     * two nulls on it would read back the very blocks we want to stop touching.
     */
    @Transactional
    public int prune() {
        List<Long> ids = findPrunable();
        if (ids.isEmpty()) {
            return 0;
        }

        for (int index = 0; index < ids.size(); index += BATCH_SIZE) {
            scans.dropPayloads(ids.subList(index, Math.min(index + BATCH_SIZE, ids.size())));
        }

        RetentionPolicy policy = policy();
        log.info(
                "Retention: raw payloads dropped for {} scan(s) (keeping {} per target, maximum age {} days).",
                ids.size(),
                policy.keepPerTarget(),
                policy.maxAge().toDays());
        return ids.size();
    }

    /** How many scans still carry a raw payload — the figure the screen shows. */
    @Transactional(readOnly = true)
    public long payloadCount() {
        return scans.countPayloadBearing();
    }

    /**
     * A scan with neither target is grouped as a repository with id zero.
     *
     * <p>It cannot happen through any code path, and it must not throw here: the purge runs on
     * the maintenance tick, and one impossible row taking the tick down would also stop the
     * outbox relay and the triage expiry that share it.
     */
    private static ScanTarget targetOf(Object[] row) {
        if (row[1] != null) {
            return new ScanTarget.Repository(((Number) row[1]).longValue());
        }
        if (row[2] != null) {
            return new ScanTarget.Container(((Number) row[2]).longValue());
        }
        return new ScanTarget.Repository(0);
    }
}
