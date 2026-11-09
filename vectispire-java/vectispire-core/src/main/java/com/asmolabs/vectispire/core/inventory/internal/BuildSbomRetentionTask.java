package com.asmolabs.vectispire.core.inventory.internal;

import com.asmolabs.vectispire.common.domain.retention.EvidenceRetention;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.inventory.BuildSbomInventory;
import com.asmolabs.vectispire.core.maintenance.MaintenanceTask;
import com.asmolabs.vectispire.core.settings.SettingsService;
import java.time.Clock;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/**
 * The build SBOMs, purged past the evidence window.
 *
 * <p><b>{@code evidence_retention_days}, the dial of the other evidence</b> — the verdicts, the compliance
 * captures, the report runs' exports: an SBOM is what a checklist line's automatic answer and an inventory
 * row rest on, kept as long as an assessor may ask what they rested on. Zero purges nothing. A pipeline
 * sends one per build, a few hundred kilobytes of components apiece; without this the table holds every
 * build ever made.
 *
 * <p>The scans' inventories keep what each SBOM gave them ({@link BuildSbomInventory#purgeImportedBefore}).
 * Never throws; a failure skips the purge for the turn, and the next turn removes what this one left.
 */
@Component
@Order(MaintenanceTask.Sequence.BUILD_SBOM_RETENTION)
public class BuildSbomRetentionTask implements MaintenanceTask {

    private static final Logger log = LoggerFactory.getLogger(BuildSbomRetentionTask.class);

    private final BuildSbomInventory builds;
    private final SettingsService settings;
    private final Clock clock;

    public BuildSbomRetentionTask(BuildSbomInventory builds, SettingsService settings, Clock clock) {
        this.builds = builds;
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
                    .map(builds::purgeImportedBefore)
                    .orElse(0);
            if (purged > 0) {
                log.info("Maintenance: {} build SBOM(s) past the evidence window removed.", purged);
            }
        } catch (RuntimeException failed) {
            log.warn("Build SBOM purge skipped: {}", failed.getMessage());
        }
    }
}
