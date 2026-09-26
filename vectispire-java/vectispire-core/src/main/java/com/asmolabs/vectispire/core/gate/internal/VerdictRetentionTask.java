package com.asmolabs.vectispire.core.gate.internal;

import com.asmolabs.vectispire.common.domain.retention.EvidenceRetention;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.gate.persistence.GateVerdicts;
import com.asmolabs.vectispire.core.maintenance.MaintenanceTask;
import com.asmolabs.vectispire.core.settings.SettingsService;
import java.time.Clock;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/**
 * The gate's verdict register, purged past the evidence window.
 *
 * <p><b>Its own task since step 5, no longer a port of the authentication tables' pass.</b> That pass
 * purged the register because it had always done so: first by reading {@code GateVerdicts} while the
 * code was packaged by layer, then — once the register was this module's and the read closed a cycle
 * — through a port {@code access} declared and this module implemented. A lower module purging a
 * higher one's table through an interface was the indirection the periodic tick's own port removes:
 * the gate contributes what it needs run, and {@code access} knows nothing of verdicts (decision 0029).
 *
 * <p><b>This table grows with the build rate, not with the estate.</b> A pipeline asks the gate on
 * every push, so a busy fortnight writes more rows than a year of scanning does. Without a purge the
 * register that proves the control works becomes the largest table in the database, and the first
 * thing an operator deletes by hand — which destroys the proof.
 *
 * <p><b>One dial for all evidence, {@code evidence_retention_days}, and not the payload window.</b> A
 * payload is bulky and reproducible, a verdict is tiny and gone for good: the payload default of
 * ninety days would have emptied this register months before an annual assessment asked to see it —
 * see {@link EvidenceRetention}. The compliance captures read the same setting ({@code
 * SnapshotRetentionTask}); two windows would invite the drift the single dial exists to prevent. Zero
 * purges nothing.
 *
 * <p><b>Never throws.</b> A failure skips this table for the turn and not the tasks after it, as it
 * did inside the pass.
 */
@Component
@Order(MaintenanceTask.Sequence.GATE_VERDICTS)
public class VerdictRetentionTask implements MaintenanceTask {

    private static final Logger log = LoggerFactory.getLogger(VerdictRetentionTask.class);

    private final GateVerdicts verdicts;
    private final SettingsService settings;
    private final Clock clock;

    public VerdictRetentionTask(GateVerdicts verdicts, SettingsService settings, Clock clock) {
        this.verdicts = verdicts;
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
                    .map(verdicts::deleteBefore)
                    .orElse(0);
            if (purged > 0) {
                log.info("Maintenance: {} aged gate verdict(s) removed.", purged);
            }
        } catch (RuntimeException failed) {
            log.warn("Gate verdict purge skipped: {}", failed.getMessage());
        }
    }
}
