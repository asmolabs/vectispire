package com.asmolabs.vectispire.core.reportplugins.internal;

import com.asmolabs.vectispire.common.domain.retention.EvidenceRetention;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.maintenance.MaintenanceTask;
import com.asmolabs.vectispire.core.reportplugins.persistence.ReportDocumentRepository;
import com.asmolabs.vectispire.core.reportplugins.persistence.ReportExportRepository;
import com.asmolabs.vectispire.core.settings.SettingsService;
import java.time.Clock;
import java.time.Instant;
import java.util.Optional;
import java.util.function.Function;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/**
 * The exports report runs were given and the documents they produced, purged past the evidence window (decision
 * 0035 §3, answer 7).
 *
 * <p><b>{@code evidence_retention_days}, the dial of the other evidence</b> — the verdicts, the compliance
 * captures, the weekly OWASP record: an export is what a document's provenance attests to, and kept as long as an
 * assessor may ask for the document; the document as long as somebody may ask for it again. Zero purges nothing.
 * <b>The bytes only</b>: the run's row keeps the export's, the output's and the package's digests and everything
 * else it recorded, as long as the audit log keeps the entries naming it.
 *
 * <p>Up to 64 MiB of export and 50 MiB of document a row, one per produced report: without this the tables hold
 * every project's whole state at every report ever rendered. Never throws; a failure skips its table for the turn,
 * and the next turn removes what this one left.
 */
@Component
@Order(MaintenanceTask.Sequence.REPORT_EVIDENCE_RETENTION)
public class ReportEvidenceRetentionTask implements MaintenanceTask {

    private static final Logger log = LoggerFactory.getLogger(ReportEvidenceRetentionTask.class);

    private final ReportExportRepository exports;
    private final ReportDocumentRepository documents;
    private final SettingsService settings;
    private final Clock clock;

    public ReportEvidenceRetentionTask(ReportExportRepository exports, ReportDocumentRepository documents,
            SettingsService settings, Clock clock) {
        this.exports = exports;
        this.documents = documents;
        this.settings = settings;
        this.clock = clock;
    }

    @Override
    public Cadence cadence() {
        return Cadence.HOURLY;
    }

    @Override
    public void run() {
        Optional<Instant> cutoff;
        try {
            cutoff = EvidenceRetention.cutoff(settings.asInt(Setting.EVIDENCE_RETENTION_DAYS), clock.instant());
        } catch (RuntimeException failed) {
            log.warn("Report evidence purge skipped: {}", failed.getMessage());
            return;
        }
        purge("export", cutoff, exports::deleteCreatedBefore);
        purge("document", cutoff, documents::deleteCreatedBefore);
    }

    /** One table's purge, on its own: a failure of the exports' does not keep the documents for another turn. */
    private static void purge(String what, Optional<Instant> cutoff, Function<Instant, Integer> delete) {
        try {
            int purged = cutoff.map(delete).orElse(0);
            if (purged > 0) {
                log.info("Maintenance: {} report {}(s) past the evidence window removed.", purged, what);
            }
        } catch (RuntimeException failed) {
            log.warn("Report {} purge skipped: {}", what, failed.getMessage());
        }
    }
}
