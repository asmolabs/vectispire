package com.asmolabs.zanshin.common.domain.graph;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("the Blast Radius calculation and domain models")
class BlastRadiusReportTest {

    @Test
    @DisplayName("calculates blast radius score correctly")
    void calculatesScore() {
        int scoreZero = BlastRadiusReport.calculateScore(0, 0, 0, 0, 0.0);
        assertThat(scoreZero).isZero();

        // 3 targets, 2 direct, 1 transitive, CVSS 9.8
        int highImpactScore = BlastRadiusReport.calculateScore(3, 2, 1, 4, 9.8);
        assertThat(highImpactScore).isGreaterThan(70);
        assertThat(highImpactScore).isLessThanOrEqualTo(100);
    }

    @Test
    @DisplayName("builds and instantiates BlastRadiusReport")
    void buildsReport() {
        DependencyGraph.GraphNode targetNode = new DependencyGraph.GraphNode(
                "target-1", "corp/backend", "TARGET", "main", "GIT", 80, true, List.of());
        DependencyGraph.GraphNode pkgNode = new DependencyGraph.GraphNode(
                "pkg-1", "commons-text", "PACKAGE", "1.9", "Maven", 90, true, List.of("CVE-2022-42889"));

        DependencyGraph.GraphEdge edge = new DependencyGraph.GraphEdge("target-1", "pkg-1", "DEPENDS_ON");
        DependencyGraph graph = new DependencyGraph(List.of(targetNode, pkgNode), List.of(edge));

        BlastRadiusReport.TargetImpact targetImpact = new BlastRadiusReport.TargetImpact(
                1L, "REPOSITORY", "corp/backend", "main", "pom.xml", "pkg:maven/org.apache.commons/commons-text@1.9", "commons-text", "1.9", true, List.of("CVE-2022-42889"), "REACHABLE", 42L);

        BlastRadiusReport report = new BlastRadiusReport(
                "commons-text",
                "PACKAGE",
                1,
                1,
                0,
                1,
                65,
                List.of(targetImpact),
                graph);

        assertThat(report.query()).isEqualTo("commons-text");
        assertThat(report.totalTargetsAffected()).isEqualTo(1);
        assertThat(report.graph().nodes()).hasSize(2);
        assertThat(report.graph().edges()).hasSize(1);
    }
}
