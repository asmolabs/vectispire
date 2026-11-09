package com.asmolabs.vectispire.core.issues;

import com.asmolabs.vectispire.core.issues.persistence.TriageEventRepository;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * From when the triage history holds every reopening — what lets a count of reopenings say "none" rather
 * than "none recorded".
 *
 * <p>Before V68 a scan that found a resolved issue again reopened it and wrote nothing; since, each
 * reopening is an entry of origin {@code reopen}. Nothing in the history can say where that began: a week
 * without an entry reads the same whether nothing came back or nothing was written. The migration's own
 * application can — V68 and the code writing the entries arrived together, and Flyway runs before the
 * application serves anything.
 */
@Service
public class ReopeningsRecord {

    /**
     * The margin added to the migration's instant. Flyway stores it as a timestamp without a zone — the
     * server's on PostgreSQL, the session's on MySQL — and the driver reads it in the JVM's, off by up to
     * fourteen hours when they differ. A day later is never too early; a reader that asks about whole weeks
     * loses at most the week of the upgrade, whose first days were not recorded anyway.
     */
    static final Duration MARGIN = Duration.ofDays(1);

    private final TriageEventRepository events;

    public ReopeningsRecord(TriageEventRepository events) {
        this.events = events;
    }

    /**
     * The instant from which every reopening has an entry, or empty when that is not known — no V68 row in
     * Flyway's history, or a failed one — in which case no figure of reopenings is a figure.
     */
    @Transactional(readOnly = true)
    public Optional<Instant> recordedSince() {
        return events.reopeningMigrationInstalledOn().stream()
                .min(Instant::compareTo)
                .map(installed -> installed.plus(MARGIN));
    }
}
