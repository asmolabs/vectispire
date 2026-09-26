package com.asmolabs.vectispire.core.compliance.internal;

import com.asmolabs.vectispire.common.domain.retention.EvidenceRetention;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.compliance.persistence.ComplianceSnapshotRepository;
import com.asmolabs.vectispire.core.maintenance.MaintenanceTask;
import com.asmolabs.vectispire.core.settings.SettingsService;
import java.time.Clock;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/**
 * The monthly compliance captures, purged past the evidence window.
 *
 * <p>The gate's {@code VerdictRetentionTask} says why this is a task of its own since step 5 and why
 * both read one dial, {@code evidence_retention_days}: a capture is the record an assessment reads,
 * not a blob that scanning again regenerates. Never throws; a failure skips this table for the turn.
 */
@Component
@Order(MaintenanceTask.Sequence.COMPLIANCE_SNAPSHOTS)
public class SnapshotRetentionTask implements MaintenanceTask {

    private static final Logger log = LoggerFactory.getLogger(SnapshotRetentionTask.class);

    private final ComplianceSnapshotRepository snapshots;
    private final SettingsService settings;
    private final Clock clock;

    public SnapshotRetentionTask(ComplianceSnapshotRepository snapshots, SettingsService settings, Clock clock) {
        this.snapshots = snapshots;
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
                    .map(snapshots::deleteBefore)
                    .orElse(0);
            if (purged > 0) {
                log.info("Maintenance: {} compliance snapshot(s) past the evidence window removed.", purged);
            }
        } catch (RuntimeException failed) {
            log.warn("Compliance snapshot purge skipped: {}", failed.getMessage());
        }
    }
}
