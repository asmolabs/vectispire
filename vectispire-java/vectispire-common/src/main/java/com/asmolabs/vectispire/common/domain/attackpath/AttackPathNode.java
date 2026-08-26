package com.asmolabs.vectispire.common.domain.attackpath;

import java.util.Map;

/**
 * An individual entity in an attack chain (Ingress, API endpoint, vulnerable dependency, secret, or database).
 */
public record AttackPathNode(
        String id,
        String label,
        AttackPathNodeType type,
        String severity,
        boolean isExploitable,
        String subtitle,
        Map<String, String> metadata) {}
