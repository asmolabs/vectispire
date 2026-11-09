package com.asmolabs.vectispire.common.domain.compliance;

import java.util.List;

/**
 * Result of evaluating one compliance framework.
 *
 * <p>{@code scorePercentage} is zero wherever the status is {@link ComplianceControl.Status#NO_DATA}, on
 * a control and on the framework: no measurement, not a measured zero — read the status first.
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
