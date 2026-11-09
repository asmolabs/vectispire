package com.asmolabs.vectispire.core.gate;

import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.gate.persistence.GateVerdictEntity;
import java.time.Instant;
import java.util.UUID;

/**
 * One answer of the gate's register as the layers above the services hold it: the row's
 * properties under their own names, not the row.
 */
public record GateVerdictView(
        UUID id,
        Long repoId,
        Long containerId,
        boolean passed,
        int evaluated,
        int violations,
        long criticalCount,
        long highCount,
        long mediumCount,
        long lowCount,
        String failOnSeverity,
        String policySource,
        Long policyVersion,
        boolean relaxationsIgnored,
        Instant decidedAt,
        String decidedBy,
        String ipAddress) {

    /**
     * The target the verdict was given about, or null for a row that names none.
     *
     * <p>The gate records none such: its one writer takes a {@code ScanTarget}, and deleting a target
     * deletes its verdicts ({@code fk_gate_verdict_repo}, {@code fk_gate_verdict_container}). But both
     * columns are nullable and no check requires one, so a row written by hand or restored from elsewhere
     * can hold neither. Read as "a repository, else a container", such a row unboxed a null container id
     * and answered the whole register — the screen and section 09 of the evidence bundle — with a 500, the
     * defect the exceptions register had (7e7a3fd4). A null target is listed to a reader of the whole
     * estate and refused to a restricted one by {@code Visibility.permits}.
     */
    public ScanTarget target() {
        if (repoId != null) {
            return new ScanTarget.Repository(repoId);
        }
        return containerId == null ? null : new ScanTarget.Container(containerId);
    }

    public static GateVerdictView of(GateVerdictEntity row) {
        return new GateVerdictView(
                row.getId(),
                row.getRepoId(),
                row.getContainerId(),
                row.isPassed(),
                row.getEvaluated(),
                row.getViolations(),
                row.getCriticalCount(),
                row.getHighCount(),
                row.getMediumCount(),
                row.getLowCount(),
                row.getFailOnSeverity(),
                row.getPolicySource(),
                row.getPolicyVersion(),
                row.isRelaxationsIgnored(),
                row.getDecidedAt(),
                row.getDecidedBy(),
                row.getIpAddress());
    }
}
