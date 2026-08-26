package com.asmolabs.vectispire.common.domain.attackpath;

/**
 * A directional relationship between two nodes in an attack path.
 */
public record AttackPathEdge(
        String id,
        String source,
        String target,
        String label,
        boolean isCriticalPath) {}
