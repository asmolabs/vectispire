package com.asmolabs.vectispire.common.domain.attackpath;

import java.util.List;

/**
 * A concrete end-to-end attack scenario from external exposure to asset compromise.
 */
public record AttackPath(
        String id,
        String title,
        String description,
        String riskLevel,
        boolean isDirectlyExploitable,
        List<String> nodeIds,
        String remediationAdvice) {}
