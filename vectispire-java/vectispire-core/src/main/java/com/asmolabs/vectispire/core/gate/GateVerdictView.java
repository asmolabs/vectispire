package com.asmolabs.vectispire.core.gate;

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
