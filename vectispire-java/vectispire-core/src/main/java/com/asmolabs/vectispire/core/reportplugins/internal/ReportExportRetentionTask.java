package com.asmolabs.vectispire.core.reportplugins.internal;

import com.asmolabs.vectispire.common.domain.retention.EvidenceRetention;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.maintenance.MaintenanceTask;
import com.asmolabs.vectispire.core.reportplugins.persistence.ReportExportRepository;
import com.asmolabs.vectispire.core.settings.SettingsService;
import java.time.Clock;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/**
 * The exports report runs were given, purged past the evidence window (decision 0035 §3, answer 7).
 *
 * <p><b>{@code evidence_retention_days}, the dial of the other evidence</b> — the verdicts, the compliance
 * captures, the weekly OWASP record: an export is what a document's provenance attests to, and kept as long as an
 * assessor may ask for the document. Zero purges nothing. <b>The bytes only</b>: the run's row keeps the export's
 * digest, its size and everything else it recorded, as long as the audit log keeps the entries naming it.
 *
 * <p>Up to 64 MiB a row, one per produced report: without this the table holds every project's whole state at
 * every report ever rendered. Never throws; a failure skips the table for the turn, and the next turn removes what
 * this one left.
 */
@Component
@Order(MaintenanceTask.Sequence.REPORT_EXPORT_RETENTION)
public class ReportExportRetentionTask implements MaintenanceTask {

    private static final Logger log = LoggerFactory.getLogger(ReportExportRetentionTask.class);

    private final ReportExportRepository exports;
    private final SettingsService settings;
    private final Clock clock;

    public ReportExportRetentionTask(ReportExportRepository exports, SettingsService settings, Clock clock) {
        this.exports = exports;
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
                    .map(exports::deleteCreatedBefore)
                    .orElse(0);
            if (purged > 0) {
                log.info("Maintenance: {} report export(s) past the evidence window removed.", purged);
            }
        } catch (RuntimeException failed) {
            log.warn("Report export purge skipped: {}", failed.getMessage());
        }
    }
}
