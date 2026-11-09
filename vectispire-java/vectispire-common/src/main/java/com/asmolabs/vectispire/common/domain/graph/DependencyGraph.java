package com.asmolabs.vectispire.common.domain.graph;

import java.util.List;

/**
 * Pure domain representation of a multi-echelon dependency relationship graph.
 */
public record DependencyGraph(
        List<GraphNode> nodes,
        List<GraphEdge> edges) {

    public record GraphNode(
            String id,
            String label,
            String type, // "TARGET", "PACKAGE", "CVE"
            String version,
            String ecosystem,
            int riskScore,
            boolean isDirect,
            List<String> cves) {}

    public record GraphEdge(
            String source,
            String target,
            String relationship) {} // "DEPENDS_ON", "VULNERABLE_TO"
}
