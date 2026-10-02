package com.asmolabs.vectispire.core.compliance.internal;

import com.asmolabs.vectispire.common.domain.retention.EvidenceRetention;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.compliance.OwaspWeeklyCoverageService;
import com.asmolabs.vectispire.core.maintenance.MaintenanceTask;
import com.asmolabs.vectispire.core.settings.SettingsService;
import java.time.Clock;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/**
 * The weekly OWASP record, purged past the evidence window.
 *
 * <p><b>The same dial as the verdicts and the monthly captures, {@code evidence_retention_days}.</b>
 * The record is what a reader shows an assessor as the grid's state in a past week, and like those it
 * cannot be recomputed: the state depended on settings and rules that have moved since (V67). A
 * window of its own would let the heatmap and the captures beside it cover different periods; the
 * payload window would empty it long before an annual assessment. Zero purges nothing.
 *
 * <p><b>It grows with the estate, ten rows per target and week</b> — some five hundred per target and
 * year — and before this task only a target's deletion removed any. Never throws; a failure skips this
 * table for the turn, and the next turn removes what this one left.
 */
@Component
@Order(MaintenanceTask.Sequence.OWASP_WEEKLY_RETENTION)
public class OwaspWeeklyRetentionTask implements MaintenanceTask {

    private static final Logger log = LoggerFactory.getLogger(OwaspWeeklyRetentionTask.class);

    private final OwaspWeeklyCoverageService weekly;
    private final SettingsService settings;
    private final Clock clock;

    public OwaspWeeklyRetentionTask(OwaspWeeklyCoverageService weekly, SettingsService settings, Clock clock) {
        this.weekly = weekly;
        this.settings = settings;
        this.clock = clock;
    }

    @Override
    public Cadence cadence() {
        return Cadence.HOURLY;
    }

    @Override
    public void run() {
        try {
            int purged = EvidenceRetention.cutoff(settings.asInt(Setting.EVIDENCE_RETENTION_DAYS), clock.instant())
                    .map(weekly::purgeEndedBefore)
                    .orElse(0);
            if (purged > 0) {
                log.info("Maintenance: {} weekly OWASP coverage row(s) past the evidence window removed.", purged);
            }
        } catch (RuntimeException failed) {
            log.warn("Weekly OWASP coverage purge skipped: {}", failed.getMessage());
        }
    }
}
