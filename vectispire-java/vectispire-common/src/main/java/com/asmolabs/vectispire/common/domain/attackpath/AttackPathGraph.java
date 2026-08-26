package com.asmolabs.vectispire.common.domain.attackpath;

import java.util.List;

/**
 * The consolidated attack graph representation for a target repository or container.
 */
public record AttackPathGraph(
        Long targetId,
        String targetName,
        int totalPaths,
        int criticalExploitablePaths,
        int riskScore,
        List<AttackPathNode> nodes,
        List<AttackPathEdge> edges,
        List<AttackPath> attackPaths) {}
