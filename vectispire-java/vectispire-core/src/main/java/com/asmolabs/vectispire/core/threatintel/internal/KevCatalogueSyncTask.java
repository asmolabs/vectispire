package com.asmolabs.vectispire.core.threatintel.internal;

import com.asmolabs.vectispire.common.domain.threatintel.ThreatIntelSyncStatus.State;
import com.asmolabs.vectispire.core.maintenance.MaintenanceTask;
import com.asmolabs.vectispire.core.threatintel.ThreatIntelFeedService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/**
 * The CISA KEV catalogue, read again once it is six hours old.
 *
 * <p><b>Without this the feed was only ever as fresh as the last time somebody pressed a button</b>
 * — and before that, a list typed into the code, so {@code CRITICAL_KEV_DETECTED} fired for ten CVE
 * and never for one CISA added since. Every hourly turn asks; the feed service decides whether a
 * synchronisation is due and which instance runs it ({@code ThreatIntelFeedService.syncIfDue}), so
 * most turns cost one conditional update.
 *
 * <p>After the triage expiry and the digest, and before nothing that reads exploitation within the
 * same turn: the catalogue fetch takes up to the outbound timeout, and only the orphaned rows wait
 * behind it. Never throws; a failure is recorded on the feed's status and audited, and the next
 * attempt is half an hour away.
 */
@Component
@Order(MaintenanceTask.Sequence.KEV_CATALOGUE)
public class KevCatalogueSyncTask implements MaintenanceTask {

    private static final Logger log = LoggerFactory.getLogger(KevCatalogueSyncTask.class);

    private final ThreatIntelFeedService feed;

    public KevCatalogueSyncTask(ThreatIntelFeedService feed) {
        this.feed = feed;
    }

    @Override
    public Cadence cadence() {
        return Cadence.HOURLY;
    }

    @Override
    public void run() {
        try {
            feed.syncIfDue().ifPresent(status -> {
                if (status.status() == State.SYNCED) {
                    log.info("Maintenance: KEV catalogue {} synchronised, {} issue(s) re-evaluated.",
                            status.kevCatalogVersion(), status.backlogUpdatedCount());
                }
            });
        } catch (RuntimeException failed) {
            log.warn("KEV catalogue synchronisation skipped: {}", failed.getMessage());
        }
    }
}
