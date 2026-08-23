package com.asmolabs.zanshin.common.domain.compliance;

import java.util.List;

/**
 * Result of evaluating one compliance framework.
 */
public record ComplianceEvaluation(
        ComplianceFramework framework,
        int scorePercentage,
        ComplianceControl.Status overallStatus,
        List<ControlAssessment> controls) {

    public record ControlAssessment(
            ComplianceControl control,
            ComplianceControl.Status status,
            int scorePercentage,
            String details,
            String remediationGuidance) {}
}
