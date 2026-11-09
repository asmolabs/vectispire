package com.asmolabs.vectispire.core.threatintel.internal;

import com.asmolabs.vectispire.common.domain.threatintel.ThreatIntelSyncStatus.State;
import com.asmolabs.vectispire.core.maintenance.MaintenanceTask;
import com.asmolabs.vectispire.core.threatintel.ThreatIntelFeedService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/**
 * FIRST's EPSS file, read again once a day.
 *
 * <p><b>Without this the scores would be as old as the last button press</b> — and before the file
 * was synchronised, every scan asked {@code api.first.org} about its own CVE. Every hourly turn asks;
 * the feed decides whether a synchronisation is due and which instance runs it ({@code
 * ThreatIntelFeedService.syncEpssIfDue}), so most turns cost one conditional update.
 *
 * <p>After the KEV catalogue, and before the orphaned rows: the download and the write take seconds
 * to a minute, and only the orphaned rows wait behind them. Never throws; a failure is recorded on
 * the feed's status and audited, and the next attempt is an hour away.
 */
@Component
@Order(MaintenanceTask.Sequence.EPSS_SCORES)
public class EpssScoresSyncTask implements MaintenanceTask {

    private static final Logger log = LoggerFactory.getLogger(EpssScoresSyncTask.class);

    private final ThreatIntelFeedService feed;

    public EpssScoresSyncTask(ThreatIntelFeedService feed) {
        this.feed = feed;
    }

    @Override
    public Cadence cadence() {
        return Cadence.HOURLY;
    }

    @Override
    public void run() {
        try {
            feed.syncEpssIfDue().ifPresent(status -> {
                if (status.epss().status() == State.SYNCED) {
                    log.info("Maintenance: EPSS scores of {} ({}) in use, {} issue(s) re-scored.",
                            status.epss().scoreDate(), status.epss().modelVersion(),
                            status.epss().backlogUpdatedCount());
                }
            });
        } catch (RuntimeException failed) {
            log.warn("EPSS synchronisation skipped: {}", failed.getMessage());
        }
    }
}
